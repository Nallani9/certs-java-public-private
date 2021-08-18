package com.hobbyproject.service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyPairGeneration {

    public void generatePrivateAndPublicKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();

        String outFile = "";
        FileOutputStream out;
        out = new FileOutputStream(outFile + "byJava.key");
        out.write(pvt.getEncoded());
        out.close();

        out = new FileOutputStream(outFile + "byJava.pub");
        out.write(pvt.getEncoded());
        out.close();

        // prints "Private key format: PKCS#8" on my machine
        System.err.println("Private key format: " + pvt.getFormat());

        // prints "Public key format: X.509" on my machine
        System.err.println("Public key format: " + pub.getFormat());

        /* Read all bytes from the private key file */
        Path path = Paths.get("byJava.key");
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvtkey = kf.generatePrivate(ks);

        /* Read all the public key bytes */
        Path pathPublic = Paths.get("byJava.pub");
        byte[] bytess = Files.readAllBytes(pathPublic);

        /* Generate public key. */
        X509EncodedKeySpec kss = new X509EncodedKeySpec(bytess);
        KeyFactory kfy = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kfy.generatePublic(kss);

/* Save the keys in text format by encoding the data in Base64
        Base64.Encoder encoder = Base64.getEncoder();
        Writer out = new FileWriter(outFile + ".key");
        out.write("-----BEGIN RSA PRIVATE KEY-----\n");
        out.write(encoder.encodeToString(pvt.getEncoded()));
        out.write("\n-----END RSA PRIVATE KEY-----\n");
        out.close();

        out = new FileWriter(outFile + ".pub");
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(kp.getPublic()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();*/

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(pvtkey);

        InputStream in = null;
        try {
            in = new FileInputStream("byJava.key");
            byte[] buf = new byte[2048];
            int len;
            while ((len = in.read(buf)) != -1) {
                sign.update(buf, 0, len);
            }
        } finally {
            if (in != null) in.close();
        }

        OutputStream outs = null;
        try {
            out = new FileOutputStream("signFile");
            byte[] signature = sign.sign();
            out.write(signature);
        } finally {
            if (out != null) out.close();
        }
    }
}
