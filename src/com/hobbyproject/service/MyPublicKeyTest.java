package com.hobbyproject.service;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class MyPublicKeyTest {

    // Certificate should be PEM
    // CSR will not work
    public static PublicKey publicKeyFromFile(){
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            FileInputStream fileInputStream = new FileInputStream("request.pem");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            //System.out.println(certificate);
            System.out.println(certificate.getPublicKey());
            return certificate.getPublicKey();
        }catch (Exception e){
            System.out.println("public key error");
        }
        return null;
    }
    // Certificate should be PEM
    // CSR will not work
    public static X509Certificate publicKeyFromString(String certString) throws CertificateException {
        byte[] decoded = Base64.getDecoder().decode(certString);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
        System.out.println(certificate);
        return certificate;
    }

    // using bouncycastle to generate public key
    // Certificate should be PEM
    // CSR will not work
    public static PublicKey getPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        File file = new File("request.pem");
        try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            PublicKey publicKey = factory.generatePublic(pubKeySpec);
            System.out.println(publicKey);
            return publicKey;
        }
    }
}
