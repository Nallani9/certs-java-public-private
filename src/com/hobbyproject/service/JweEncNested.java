package com.hobbyproject.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class JweEncNested {

    public static void def() throws JOSEException {

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("jwt").build(),
                new JWTClaimsSet.Builder()
                        .subject("alice")
                        .issueTime(new Date())
                        .issuer("https://c2id.com")
                        .build());

        // Sign the JWT
        signedJWT.sign(new RSASSASigner(MyPrivateKeyTest.createPrivateKeyFromFileWithBouncy()));

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT") // required to indicate nested JWT
                        .build(),
                new Payload(signedJWT));

        // Encrypt with the recipient's public key
        jweObject.encrypt(new RSAEncrypter((RSAPublicKey) MyPublicKeyTest.publicKeyFromFile()));

        // Serialise to JWE compact form
        String jweString = jweObject.serialize();

        System.out.println(jweString);

    }
}
