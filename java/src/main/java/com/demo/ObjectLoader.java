package com.demo;

import java.io.*;
import java.util.Base64;

// A08:Software and Data Integrity Failures — Insecure Deserialization
public class ObjectLoader {

    public static Object loadFromRequest(String base64Payload)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Payload);
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}
