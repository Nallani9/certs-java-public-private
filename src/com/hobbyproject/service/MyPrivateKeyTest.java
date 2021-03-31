package com.hobbyproject.service;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class MyPrivateKeyTest {
    //WORKING
    public static PrivateKey createPrivateKeyFromFileWithBouncy(){
        PEMParser reader = null;
        try{
            reader = new PEMParser(new FileReader("key.pem"));
            PEMKeyPair keys =(PEMKeyPair) reader.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey privateKey = converter.getPrivateKey(keys.getPrivateKeyInfo());
            System.out.println(privateKey);
            return privateKey;
        }catch (Exception e){
            System.out.println("error");
        }
        return null;
    }
    // works if secret is PKSC8 format
    // only PKSC8
    public static PrivateKey getPrivateKeyForPKCS8() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        File file = new File("key-pkcs8.txt");
        try (FileReader keyReader = new FileReader(file); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
            PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
            System.out.println(privateKey);
            return privateKey;
        }
    }
    //WORKING
    public static RSAPrivateKey getPrivateKeyFromBouncy2() {
        PEMParser reader = null;
        try {

            reader = new PEMParser(new FileReader("key.pem"));
            PrivateKeyInfo info = null;
            // the return type depends on whether the file contains a single key or a key pair
            Object bouncyCastleResult = reader.readObject();
            if (bouncyCastleResult instanceof PrivateKeyInfo) {
                info = (PrivateKeyInfo) bouncyCastleResult;
            } else if ( bouncyCastleResult instanceof PEMKeyPair ) {
                PEMKeyPair keys = (PEMKeyPair) bouncyCastleResult;
                info = keys.getPrivateKeyInfo();
            } else {
                throw new Exception("No private key found in the provided file");
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey privateKeyJava = converter.getPrivateKey(info);
            System.out.println(privateKeyJava);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                }
            }
        }
        return null;
    }
}
