package com.da.iam.utils;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.springframework.security.config.Elements.JWT;

@Component
public class RSAKeyUtil {
    private static final String PRIVATE_KEY_PATH = "src/main/resources/keys/private.pem";
    private static final String PUBLIC_KEY_PATH = "src/main/resources/keys/public.pem";

    public PrivateKey getPrivateKey() {
        String privateKeyPEM = null;
        KeyFactory keyFactory = null;
        PKCS8EncodedKeySpec spec = null;
        try {
            privateKeyPEM = new String(Files.readAllBytes(Paths.get(PRIVATE_KEY_PATH))).replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
            spec = new PKCS8EncodedKeySpec(keyBytes);
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (IOException |
                 NoSuchAlgorithmException |
                 InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey getPublicKey() throws Exception {
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(PUBLIC_KEY_PATH))).replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
}
