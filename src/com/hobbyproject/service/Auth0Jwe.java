package com.hobbyproject.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Auth0Jwe {

    public static void testAuth0RSASign(){
        RSAPublicKey publicKey = (RSAPublicKey) MyPublicKeyTest.publicKeyFromFile();//Get the key instance
        RSAPrivateKey privateKey = (RSAPrivateKey) MyPrivateKeyTest.createPrivateKeyFromFileWithBouncy();//Get the key instance

        try {
            Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
            String token = JWT.create()
                    .withIssuer("sri")
                    .sign(algorithm);
            System.out.println(token);
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
    }
}
