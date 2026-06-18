package com.example.pocketsshagent.termux;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.Looper;

import com.example.pocketsshagent.IPocketAgent;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;

public class PocketAgentBridge {

    private static volatile IPocketAgent agent;
    private static final CountDownLatch serviceLatch = new CountDownLatch(1);

    public static void main(String[] args) throws Exception {
        Looper.prepareMainLooper();

        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Method systemMain = atClass.getMethod("systemMain");
        Object at = systemMain.invoke(null);
        Method getCtx = atClass.getMethod("getSystemContext");
        Context context = (Context) getCtx.invoke(at);

        Intent intent = new Intent(TermuxAgentService.ACTION_BIND_AGENT);
        intent.setComponent(new ComponentName(
                "com.example.pocketsshagent",
                "com.example.pocketsshagent.termux.TermuxAgentService"));

        context.bindService(intent, new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                agent = IPocketAgent.Stub.asInterface(service);
                serviceLatch.countDown();
                System.err.println("READY");
                System.err.flush();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                agent = null;
            }
        }, Context.BIND_AUTO_CREATE);

        new Thread(PocketAgentBridge::processRequests, "stdin-reader").start();

        Looper.loop();
    }

    private static void processRequests() {
        try {
            serviceLatch.await();
        } catch (InterruptedException e) {
            System.exit(1);
            return;
        }

        try {
            DataInputStream in = new DataInputStream(System.in);
            OutputStream out = System.out;

            while (true) {
                int len;
                try {
                    len = in.readInt();
                } catch (EOFException e) {
                    break;
                }
                if (len <= 0 || len > 65536) break;

                byte[] message = new byte[len];
                in.readFully(message);

                IPocketAgent svc = agent;
                if (svc == null) {
                    writeFailure(out);
                    continue;
                }

                try {
                    byte[] response = svc.handleMessage(message);
                    out.write(response);
                    out.flush();
                } catch (Exception e) {
                    System.err.println("[pocket-agent] handleMessage failed: " + e.getMessage());
                    writeFailure(out);
                }
            }
        } catch (IOException e) {
            // stdin closed
        }
        System.exit(0);
    }

    private static void writeFailure(OutputStream out) throws IOException {
        out.write(new byte[]{0, 0, 0, 1, 5});
        out.flush();
    }
}
