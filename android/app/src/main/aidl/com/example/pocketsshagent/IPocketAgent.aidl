package com.example.pocketsshagent;

interface IPocketAgent {
    byte[] handleMessage(in byte[] message);
}
