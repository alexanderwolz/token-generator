package de.alexanderwolz.token;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class TokenGenerator {

    public static String createJwt_RS256(PrivateKey privateKey, String issuer, String subject, String audience, int expiresInSeconds) throws Exception {

        long nowInSeconds = (new Date().getTime() / 1000);
        long expiration = nowInSeconds + expiresInSeconds; //adds threshold

        String header = "{" +
                "\"alg\":\"RS256\"," +
                "\"typ\":\"JWT\"" +
                "}";

        String payload = "{" +
                "\"iss\":\"" + issuer + "\"," +
                "\"sub\":\"" + subject + "\"," +
                "\"aud\":\"" + audience + "\"," +
                "\"exp\":\"" + expiration + "\"" +
                "}";

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header64 = encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8));
        String payload64 = encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        String hashData = header64 + "." + payload64;
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(hashData.getBytes(StandardCharsets.UTF_8));

        //RSASHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload))
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        signature.update(hash);
        String signature64 = encoder.encodeToString(signature.sign());

        return hashData + "." + signature64;
    }

    public static PrivateKey getPrivateKey_PKCS8(String rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = rsaPrivateKey;
        key = key.replace("-----BEGIN PRIVATE KEY-----", "");
        key = key.replace("-----END PRIVATE KEY-----", "");
        key = key.replaceAll("\\s+", "");
        KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey_X509(String x509Key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = x509Key;
        key = key.replace("-----BEGIN PUBLIC KEY-----", "");
        key = key.replace("-----END PUBLIC KEY-----", "");
        key = key.replaceAll("\\s+", "");
        KeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }
}
