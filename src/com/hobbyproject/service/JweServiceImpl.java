package com.hobbyproject.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

public class JweServiceImpl {

    private static final String SUBJECT = "sri";
    private static final String ISSUER = "nallani";

    protected String generateToken(Map<String, Object> payload, Date issueTime, Date expireDate) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        if (payload != null) {
            for (Map.Entry<String, Object> entry : payload.entrySet()) {
                builder.claim(entry.getKey(), entry.getValue());
            }
        }

        if (expireDate != null) {
            builder.expirationTime(expireDate);
        }

        builder.subject(SUBJECT);
        builder.issueTime(issueTime);
        builder.issuer(ISSUER);

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        EncryptedJWT jwt = new EncryptedJWT(header, builder.build());
        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) MyPublicKeyTest.getPublicKey());
        try {
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate encrypted token", e);
        }
        return jwt.serialize();
    }


    public Map<String, Object> getJsonPayload(String token) throws Exception {
        EncryptedJWT jwt = null;
        try {
            jwt = EncryptedJWT.parse(token);
            RSADecrypter decrypter = new RSADecrypter(MyPrivateKeyTest.createPrivateKeyFromFileWithBouncy());
            jwt.decrypt(decrypter);
        } catch (JOSEException | ParseException e) {
        }
        return getJSONObject(jwt);
    }

    private Map<String, Object> getJSONObject(JOSEObject jose) {

        return jose.getPayload().toJSONObject();
    }

}
