package de.alexanderwolz.token;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

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
        header.put("alg", "rsa256");
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

}
