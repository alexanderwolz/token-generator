package de.alexanderwolz.token;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class TokenGenerator {

    public static String createJwt_RS256(Map<String, String> headerMap, Map<String, String> payloadMap, String privateKeyPKCS8) throws Exception {
        return createJwt_RS256(createJson(headerMap), createJson(payloadMap), privateKeyPKCS8);
    }

    public static String createJwt_RS256(String headerJson, String payloadJson, String privateKeyPKCS8) throws Exception {

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header64 = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload64 = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        String hashData = header64 + "." + payload64;
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(hashData.getBytes(StandardCharsets.UTF_8));

        //RSASHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload))
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(getPrivateKey_PKCS8(privateKeyPKCS8));
        signature.update(hash);
        String signature64 = encoder.encodeToString(signature.sign());

        return hashData + "." + signature64;
    }


    public static String createJwt_RS256(String issuer, String subject, String audience, int expiresInSeconds, String privateKeyPKCS8) throws Exception {

        long nowInSeconds = new Date().getTime() / 1000;
        long expiration = nowInSeconds + expiresInSeconds; //adds threshold

        String header = "{" +
                "\"alg\":\"RS256\"," +
                "\"typ\":\"JWT\"" +
                "}";

        String payload = "{" +
                "\"iss\":\"" + issuer + "\"," +
                "\"sub\":\"" + subject + "\"," +
                "\"aud\":\"" + audience + "\"," +
                "\"iat\":\"" + nowInSeconds + "\"," +
                "\"nbf\":\"" + nowInSeconds + "\"," +
                "\"exp\":\"" + expiration + "\"" +
                "}";

        return createJwt_RS256(header, payload, privateKeyPKCS8);
    }

    public static boolean verifyJwt_RS256(String jwt, String publicKeyX509) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        System.out.println("Verifying ..");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] parts = jwt.split("\\.");
        String header64 = parts[0];
        String payload64 = parts[1];
        String signature64 = parts[2];

        System.out.println("Header: " + new String(decoder.decode(header64), StandardCharsets.UTF_8));
        System.out.println("Payload: " + new String(decoder.decode(payload64), StandardCharsets.UTF_8));

        String hashData = header64 + "." + payload64;
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(hashData.getBytes(StandardCharsets.UTF_8));

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(getPublicKey_X509(publicKeyX509));
        signature.update(hash);
        return signature.verify(decoder.decode(signature64));
    }


    private static PrivateKey getPrivateKey_PKCS8(String rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = rsaPrivateKey;
        key = key.replace("-----BEGIN PRIVATE KEY-----", "");
        key = key.replace("-----END PRIVATE KEY-----", "");
        key = key.replaceAll("\\s+", "");
        KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static PublicKey getPublicKey_X509(String x509Key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = x509Key;
        key = key.replace("-----BEGIN PUBLIC KEY-----", "");
        key = key.replace("-----END PUBLIC KEY-----", "");
        key = key.replaceAll("\\s+", "");
        KeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private static String createJson(Map<String, String> map) {
        StringBuilder json = new StringBuilder("{");

        int headerIndex = 0;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (headerIndex > 0) {
                json.append(",");
            }
            json.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\"");
            headerIndex++;
        }
        json.append("}");
        return json.toString();
    }
}
