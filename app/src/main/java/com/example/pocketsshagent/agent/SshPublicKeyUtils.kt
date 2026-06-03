package com.example.pocketsshagent.agent

import android.util.Base64
import java.security.MessageDigest
import java.security.PublicKey

/**
 * Utilities for SSH public key formatting and display.
 */
object SshPublicKeyUtils {

    /**
     * Format a public key as an SSH authorized_keys line:
     * ssh-ed25519 <base64-encoded-key-blob> <comment>
     */
    fun formatAuthorizedKeysLine(publicKey: PublicKey, comment: String): String {
        val rawKey = SshWireFormat.extractRawEd25519PublicKey(publicKey.encoded)
        val keyBlob = SshWireFormat.encodeEd25519PublicKey(rawKey)
        val encoded = Base64.encodeToString(keyBlob, Base64.NO_WRAP)
        return "ssh-ed25519 $encoded $comment"
    }

    /**
     * Compute the SHA-256 fingerprint of a public key in OpenSSH format.
     * Returns: SHA256:<base64-hash>
     */
    fun fingerprint(publicKey: PublicKey): String {
        val rawKey = SshWireFormat.extractRawEd25519PublicKey(publicKey.encoded)
        val keyBlob = SshWireFormat.encodeEd25519PublicKey(rawKey)
        val digest = MessageDigest.getInstance("SHA-256").digest(keyBlob)
        val encoded = Base64.encodeToString(digest, Base64.NO_WRAP or Base64.NO_PADDING)
        return "SHA256:$encoded"
    }
}
