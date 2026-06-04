package ble

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// ConnectionState represents the current state of the BLE connection.
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateAuthenticating
	StateConnected
)

func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting"
	case StateAuthenticating:
		return "Authenticating"
	case StateConnected:
		return "Connected"
	default:
		return "Unknown"
	}
}

// ConnectionManager manages automatic BLE connection and reconnection.
// It wraps the BLE client and provides:
// - Automatic reconnection with exponential backoff
// - Connection health monitoring with keepalive pings
// - Thread-safe request handling
// - Fail-fast behavior when not connected
type ConnectionManager struct {
	privateKey ed25519.PrivateKey

	// BLE client (recreated on each connection attempt)
	client   *Client
	clientMu sync.Mutex

	// Connection state
	state   ConnectionState
	stateMu sync.RWMutex

	// Control channels
	stopCh    chan struct{}
	stoppedCh chan struct{}

	// Reconnection trigger
	reconnectCh chan struct{}

	// Activity tracking for keepalive
	lastActivity time.Time
	activityMu   sync.Mutex

	// Connection attempt counter
	attempt   int
	attemptMu sync.Mutex
}

const (
	// How often to send keepalive pings when idle
	keepaliveInterval = 30 * time.Second

	// Maximum backoff delay between reconnection attempts
	maxBackoff = 30 * time.Second
)

// NewConnectionManager creates a new connection manager.
// The private key is used for authentication with the phone.
func NewConnectionManager(privateKey ed25519.PrivateKey) *ConnectionManager {
	return &ConnectionManager{
		privateKey:   privateKey,
		state:        StateDisconnected,
		stopCh:       make(chan struct{}),
		stoppedCh:    make(chan struct{}),
		reconnectCh:  make(chan struct{}, 1),
		lastActivity: time.Now(),
	}
}

// Start begins the connection management loop in a background goroutine.
// Returns immediately; connection attempts happen asynchronously.
func (cm *ConnectionManager) Start() error {
	go cm.connectionLoop()
	return nil
}

// Stop gracefully shuts down the connection manager.
// Waits for all goroutines to terminate.
func (cm *ConnectionManager) Stop() {
	// Close stop channel if not already closed
	select {
	case <-cm.stopCh:
		// Already stopped
		return
	default:
		close(cm.stopCh)
	}
	
	// Wait for connection loop to finish
	<-cm.stoppedCh
}

// SendMessage sends an SSH agent message to the phone and returns the response.
// Implements the agent.Transport interface.
//
// If not yet connected, waits for reconnection before sending. Sign requests
// (type=13) get a longer wait because they also require biometric approval.
func (cm *ConnectionManager) SendMessage(msg []byte) ([]byte, error) {
	if !cm.IsConnected() {
		// Sign requests need extra time: BLE reconnect + app foreground + biometric.
		waitTimeout := 15 * time.Second
		if len(msg) > 0 && msg[0] == 13 { // SSH_AGENTC_SIGN_REQUEST
			waitTimeout = 45 * time.Second
		}
		log.Printf("BLE not connected (%s), waiting up to %v for reconnection...", cm.GetState(), waitTimeout)
		if err := cm.WaitUntilConnected(waitTimeout); err != nil {
			return nil, fmt.Errorf("BLE transport unavailable: %s (timed out after %v)", cm.GetState(), waitTimeout)
		}
	}

	// Send the message
	cm.clientMu.Lock()
	client := cm.client
	cm.clientMu.Unlock()

	if client == nil {
		return nil, fmt.Errorf("BLE client not initialized")
	}

	resp, err := client.SendMessage(msg)
	if err != nil {
		// Connection failed - trigger reconnect
		log.Printf("BLE send failed: %v - triggering reconnect", err)
		cm.triggerReconnect()
		return nil, fmt.Errorf("BLE transport error: %w", err)
	}

	cm.recordActivity()
	return resp, nil
}

// IsConnected returns true if the connection is established and authenticated.
func (cm *ConnectionManager) IsConnected() bool {
	cm.stateMu.RLock()
	defer cm.stateMu.RUnlock()
	return cm.state == StateConnected
}

// WaitUntilConnected blocks until connected or timeout expires.
func (cm *ConnectionManager) WaitUntilConnected(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-cm.stopCh:
			return fmt.Errorf("connection manager stopped")
		default:
		}
		if cm.IsConnected() {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for BLE connection")
}

// GetState returns the current connection state.
func (cm *ConnectionManager) GetState() ConnectionState {
	cm.stateMu.RLock()
	defer cm.stateMu.RUnlock()
	return cm.state
}

// connectionLoop is the main loop that manages connection lifecycle.
// Runs in a background goroutine.
func (cm *ConnectionManager) connectionLoop() {
	defer close(cm.stoppedCh)

	for {
		select {
		case <-cm.stopCh:
			log.Println("Connection manager shutting down")
			cm.disconnect()
			return
		default:
		}

		// Attempt to establish connection
		log.Println("Connecting to phone via BLE...")
		cm.setState(StateConnecting)

		err := cm.attemptConnection()

		if err == nil {
			// Connection successful
			log.Println("✓ SSH agent ready")
			cm.setState(StateConnected)
			cm.resetAttemptCounter()

			// Start monitoring
			monitorDone := make(chan struct{})
			go cm.monitorConnection(monitorDone)

			// Wait for disconnect signal or stop
			select {
			case <-cm.reconnectCh:
				log.Println("Connection lost - reconnecting...")
			case <-cm.stopCh:
				cm.disconnect()
				<-monitorDone
				return
			}

			// Stop monitoring
			cm.setState(StateDisconnected)
			cm.disconnect()
			<-monitorDone

		} else {
			// Connection failed
			// Check if it failed due to shutdown
			select {
			case <-cm.stopCh:
				log.Println("Connection cancelled during shutdown")
				return
			default:
			}
			
			log.Printf("Connection failed: %v", err)
			cm.setState(StateDisconnected)
			cm.disconnect()
		}

		// Exponential backoff before retry
		cm.incrementAttemptCounter()
		delay := cm.calculateBackoff()
		attempt := cm.getAttemptCounter()
		log.Printf("Retry %d/∞ (waiting %v)", attempt, delay.Round(100*time.Millisecond))
		select {
		case <-time.After(delay):
		case <-cm.stopCh:
			return
		}
	}
}

// attemptConnection performs a single connection attempt.
// Returns nil on success, error on failure.
// Returns immediately if stop signal is received.
func (cm *ConnectionManager) attemptConnection() error {
	// Ensure any previous client is fully disconnected
	cm.disconnect()
	
	// Small delay to let BLE stack cleanup from previous disconnect
	time.Sleep(100 * time.Millisecond)
	
	// Create new client
	cm.clientMu.Lock()
	cm.client = NewClient()
	client := cm.client
	cm.clientMu.Unlock()

	// Connect to phone (this can take up to 10+ seconds)
	// Run in goroutine so we can cancel on stop signal
	connectDone := make(chan error, 1)
	go func() {
		connectDone <- client.Connect()
	}()

	// Wait for connection or stop signal
	select {
	case err := <-connectDone:
		if err != nil {
			return fmt.Errorf("BLE connection failed: %w", err)
		}
	case <-cm.stopCh:
		// Stop signal received, disconnect and return
		client.Disconnect()
		return fmt.Errorf("connection cancelled: shutting down")
	}

	// Authenticate
	cm.setState(StateAuthenticating)
	
	// Run authentication in goroutine so we can cancel on stop
	authDone := make(chan error, 1)
	go func() {
		authDone <- client.Authenticate(cm.privateKey)
	}()

	select {
	case err := <-authDone:
		if err != nil {
			client.Disconnect()
			return fmt.Errorf("authentication failed: %w", err)
		}
	case <-cm.stopCh:
		client.Disconnect()
		return fmt.Errorf("authentication cancelled: shutting down")
	}

	cm.recordActivity()
	return nil
}

// monitorConnection sends periodic keepalive pings to detect stale connections.
func (cm *ConnectionManager) monitorConnection(done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we've had recent activity
			cm.activityMu.Lock()
			lastActive := cm.lastActivity
			cm.activityMu.Unlock()

			// If no activity for keepaliveInterval, send a ping
			if time.Since(lastActive) >= keepaliveInterval {
				cm.clientMu.Lock()
				client := cm.client
				cm.clientMu.Unlock()

				if client != nil {
					// Send REQUEST_IDENTITIES as keepalive
					_, err := client.SendMessage([]byte{11})
					if err != nil {
						log.Printf("Keepalive ping failed: %v - triggering reconnect", err)
						cm.triggerReconnect()
						return
					}
					cm.recordActivity()
				}
			}

		case <-cm.reconnectCh:
			return
		case <-cm.stopCh:
			return
		}
	}
}

// triggerReconnect signals the connection loop to reconnect.
// Safe to call multiple times (non-blocking).
func (cm *ConnectionManager) triggerReconnect() {
	select {
	case cm.reconnectCh <- struct{}{}:
	default:
		// Already triggered
	}
}

// disconnect closes the current BLE connection if open.
func (cm *ConnectionManager) disconnect() {
	cm.clientMu.Lock()
	defer cm.clientMu.Unlock()

	if cm.client != nil {
		cm.client.Disconnect()
		cm.client = nil
	}
}

// setState updates the connection state.
func (cm *ConnectionManager) setState(state ConnectionState) {
	cm.stateMu.Lock()
	defer cm.stateMu.Unlock()
	cm.state = state
}

// recordActivity updates the last activity timestamp.
func (cm *ConnectionManager) recordActivity() {
	cm.activityMu.Lock()
	defer cm.activityMu.Unlock()
	cm.lastActivity = time.Now()
}

// calculateBackoff returns the backoff delay for the current attempt.
// Uses exponential backoff with jitter: 1s → 2s → 4s → 8s → 16s → 30s (capped)
func (cm *ConnectionManager) calculateBackoff() time.Duration {
	cm.attemptMu.Lock()
	attempt := cm.attempt
	cm.attemptMu.Unlock()

	if attempt == 0 {
		return 0
	}

	// Exponential backoff: 2^(attempt-1) seconds
	delay := time.Duration(1<<uint(attempt-1)) * time.Second
	if delay > maxBackoff {
		delay = maxBackoff
	}

	// Add jitter (±10%) to avoid thundering herd
	jitter := time.Duration(rand.Float64() * 0.2 * float64(delay))
	if rand.Float64() < 0.5 {
		delay -= jitter
	} else {
		delay += jitter
	}

	return delay
}

// incrementAttemptCounter increments the retry attempt counter.
func (cm *ConnectionManager) incrementAttemptCounter() {
	cm.attemptMu.Lock()
	defer cm.attemptMu.Unlock()
	cm.attempt++
}

// resetAttemptCounter resets the retry counter to zero.
func (cm *ConnectionManager) resetAttemptCounter() {
	cm.attemptMu.Lock()
	defer cm.attemptMu.Unlock()
	cm.attempt = 0
}

// getAttemptCounter returns the current retry attempt number.
func (cm *ConnectionManager) getAttemptCounter() int {
	cm.attemptMu.Lock()
	defer cm.attemptMu.Unlock()
	return cm.attempt
}
