package de.alexanderwolz.token;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

public class TokenGenerator {

    public static String createJwt(Map<String, String> headerMap, Map<String, String> payloadMap, String privateKeyPKCS8) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        return createJwt(createJson(headerMap), createJson(payloadMap), privateKeyPKCS8);
    }

    public static String createJwt(String headerJson, String payloadJson, String privateKeyPKCS8) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header64 = encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload64 = encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        String signingInput = header64 + "." + payload64;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey_PKCS8(privateKeyPKCS8));
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        String signature64 = encoder.encodeToString(signature.sign());

        return signingInput + "." + signature64;
    }


    public static String createJwt_RS256(String issuer, String subject, String audience, int expiresInSeconds, String privateKeyPKCS8) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

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
                "\"iat\":" + nowInSeconds + "," +
                "\"nbf\":" + nowInSeconds + "," +
                "\"exp\":" + expiration +
                "}";

        return createJwt(header, payload, privateKeyPKCS8);
    }

    public static boolean verifyJwt_RS256(String jwt, String publicKeyX509) throws IOException, IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Token is not a valid JWT");
        }
        String header64 = parts[0];
        String payload64 = parts[1];
        String signature64 = parts[2];

        String signingInput = header64 + "." + payload64;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(getPublicKey_X509(publicKeyX509));
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signature.verify(decoder.decode(signature64));
    }


    private static PrivateKey getPrivateKey_PKCS8(String rsaPrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String content = readContent(rsaPrivateKey);

        if (content.contains("BEGIN RSA PRIVATE KEY")) {
            byte[] pkcs1Bytes = decodePem(content, "RSA PRIVATE KEY");
            byte[] pkcs8Bytes = wrapRsaPkcs1InPkcs8(pkcs1Bytes);
            KeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        }

        byte[] pkcs8Bytes = decodePem(content, "PRIVATE KEY");
        KeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static byte[] decodePem(String content, String label) {
        String key = content
                .replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(key);
    }

    private static byte[] wrapRsaPkcs1InPkcs8(byte[] pkcs1) {
        byte[] version = {0x02, 0x01, 0x00}; // INTEGER 0
        byte[] rsaAlgorithmIdentifier = { // SEQUENCE { OID rsaEncryption, NULL }
                0x30, 0x0D,
                0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01,
                0x05, 0x00
        };
        byte[] privateKeyOctetString = concat(new byte[]{0x04}, derLength(pkcs1.length), pkcs1);
        byte[] body = concat(version, rsaAlgorithmIdentifier, privateKeyOctetString);
        return concat(new byte[]{0x30}, derLength(body.length), body);
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }
        int numBytes = 1;
        for (int temp = length; (temp >>= 8) != 0; numBytes++) {
            // count how many bytes are needed to represent the length
        }
        byte[] result = new byte[numBytes + 1];
        result[0] = (byte) (0x80 | numBytes);
        for (int i = numBytes; i >= 1; i--) {
            result[i] = (byte) (length & 0xFF);
            length >>= 8;
        }
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] array : arrays) {
            total += array.length;
        }
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    private static PublicKey getPublicKey_X509(String x509Key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String key = readContent(x509Key);
        key = key.replace("-----BEGIN PUBLIC KEY-----", "");
        key = key.replace("-----END PUBLIC KEY-----", "");
        key = key.replaceAll("\\s+", "");
        KeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private static String readContent(String key) throws IOException {
        if(new File(key).exists()){
            return new String(Files.readAllBytes(Paths.get(key)));
        }
        return key;
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

    public static void printDecodedTokenParts(String token) {
        String[] parts = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        System.out.println("Header: " + new String(decoder.decode(parts[0]), StandardCharsets.UTF_8));
        System.out.println("Payload: " + new String(decoder.decode(parts[1]), StandardCharsets.UTF_8));
    }
}
