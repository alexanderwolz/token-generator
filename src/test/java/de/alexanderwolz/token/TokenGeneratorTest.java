package de.alexanderwolz.token;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class TokenGeneratorTest extends AbstractTest {

    @Test
    public void testCreateJwtWithStringParams() throws Exception {
        String issuer = "sso.server.com";
        String subject = "john.doe@server.com";
        String audience = "resources.server.com";
        int expiresIn = 500;
        String token = TokenGenerator.createJwt_RS256(issuer, subject, audience, expiresIn, privateKeyPkcs8File);
        System.out.println(token);
        TokenGenerator.printDecodedTokenParts(token);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509File);
        System.out.println("Token signature is valid: " + isValid);
        Assertions.assertTrue(isValid);
    }

    @Test
    public void testCreateJwtWithMapParams() throws Exception {
        Map<String, String> header = new HashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "JWT");

        Map<String, String> payload = new HashMap<>();
        payload.put("iss", "auth.server.com");
        payload.put("sub", "john.doe@server.com");
        payload.put("aud", "resources.server.com");
        payload.put("exp", String.valueOf(new Date().getTime() / 1000));

        String token = TokenGenerator.createJwt(header, payload, privateKeyPkcs8File);
        System.out.println(token);
        TokenGenerator.printDecodedTokenParts(token);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509File);
        System.out.println("Token signature is valid: " + isValid);
        Assertions.assertTrue(isValid);
    }

    @Test
    public void testCreateJwtWithPkcs1PrivateKey() throws Exception {
        // Regression test: openssl genrsa produces PKCS#1 ("BEGIN RSA PRIVATE KEY"),
        // which used to fail with a cryptic "Illegal base64 character 2d" because
        // the leftover "-----" markers of the unmatched PEM header were fed
        // straight into the Base64 decoder. private.pem and private-pkcs8.pem are
        // the same underlying key pair in different encodings (see
        // src/test/resources/Readme.txt), so this must verify against the same
        // public key as the PKCS#8 tests above.
        String token = TokenGenerator.createJwt_RS256("issuer", "subject", "audience", 500, privateKeyPkcs1File);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509File);
        Assertions.assertTrue(isValid);
    }

    @Test
    public void testExpirationClaimsAreNumericNotStrings() throws Exception {
        // RFC 7519 requires iat/nbf/exp to be JSON numbers (NumericDate), not strings.
        String token = TokenGenerator.createJwt_RS256("issuer", "subject", "audience", 500, privateKeyPkcs8File);
        String payloadJson = decodePayload(token);

        Assertions.assertTrue(Pattern.compile("\"iat\":\\d+").matcher(payloadJson).find(),
                "iat must be an unquoted number: " + payloadJson);
        Assertions.assertTrue(Pattern.compile("\"nbf\":\\d+").matcher(payloadJson).find(),
                "nbf must be an unquoted number: " + payloadJson);
        Assertions.assertTrue(Pattern.compile("\"exp\":\\d+").matcher(payloadJson).find(),
                "exp must be an unquoted number: " + payloadJson);
    }

    @Test
    public void testSignatureIsIndependentlyVerifiableAsSpecCompliantRS256() throws Exception {
        // Regression test for a real bug: the original implementation hashed the
        // signing input with SHA-256 by hand and then fed that digest into a
        // "SHA256withRSA" Signature, which hashes internally as well - producing a
        // signature over a double-hashed value. That token only validated against
        // its own (equally buggy) verify method, not against any spec-compliant
        // RS256 verifier such as Keycloak, Nimbus or jose4j.
        //
        // This test deliberately does NOT call TokenGenerator.verifyJwt_RS256 -
        // it re-implements plain RFC 7515 RS256 verification (single SHA-256,
        // performed internally by the Signature instance) from scratch, so a
        // future re-introduction of the double-hash bug would fail here even if
        // createJwt() and verifyJwt_RS256() were broken in the same way again.
        String token = TokenGenerator.createJwt_RS256("issuer", "subject", "audience", 500, privateKeyPkcs8File);
        String[] parts = token.split("\\.");
        Assertions.assertEquals(3, parts.length);

        String signingInput = parts[0] + "." + parts[1];
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

        String publicKeyPem = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(publicKeyX509File)))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        PublicKey publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyPem)));

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));

        Assertions.assertTrue(signature.verify(signatureBytes),
                "Token must verify against a spec-compliant, single-hash RS256 check");
    }

    private String decodePayload(String token) {
        String[] parts = token.split("\\.");
        return new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
    }

}
