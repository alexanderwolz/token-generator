package de.alexanderwolz.token;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenGeneratorTest {

    //openssl genrsa -out private.pem 2048
    //openssl rsa -in private.pem -pubout -out public.pem
    //openssl pkcs8 -in private.pem -topk8 -nocrypt -out private-pkcs8.pem
    //First key is PKCS1 but Java only knows PKCS8, so we need to create one using OpenSSL

    private static final String privateKeyPkcs8String = """
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqqjmYQVspXqJr
            7XLxNRKgffw0TG8Tt7JqAFsPUGQzpb/7DMGqW1O7RYPyg5QPPfCdEX1qEEBZFVpw
            Bh8dBISgsnvmZXLT6IZOEfCDWgv9lDnUWpMr4awZ6b+674Rxl2OMiwUo5Uerksnd
            tOLcllQNH4zRrTAx6mDcxgyrPP/mXHFgIJR3EVmnaSZsJuXFAk05dkBF1A9vnXhf
            zZy8tGAcc3MWbZAYFfv40WBgF6TFzmWKDKL+p0/WoqglFET+J30ZPy3uZiDbX2sg
            Z8UHuTIDScqRlGmsBfkFnedqfQYYeiIMfxHVB2vvdNY6WPoMGhYSO2kdyhszAVrH
            f6jGw14NAgMBAAECggEBAJeVSgr9/MMmbEjHY35ISDX/69Bkp0PXX5p1jFzCE1gB
            c5fZz6gZwmawKuGW+Sc3XZw4VgkTYl2pG3hNm/+EkZ+0a7CSS7By/X6ku/Y9To2J
            GCoCMBsidadvhPheC/HMVvPMQZL/OGKuOVPLqtfPC5BGlxJCi2VS/yrdjAV5K9xD
            EhpfbNo33M+ZKyP0Ry1PbCsYkHL7jtyx5hfTaITcLbBHS32ZIJYscVrqLLxZufGx
            4QkocAOXbqhNahn5YCOuIT1qiCY4lQItLWTxS50s1e9eP7UbQ58015DEt83hAnwT
            7oxs80M5XjYhVBk5uOQ5sm1ZuuAcH9aDjfViq1QPOcECgYEA9SuF1h7zX2SEx69U
            YHIgpwSvhDEw8YMWRw4Xw7G7tf7CqKF9Via5K31c99uJ61a/wKb4+2iq2XlxqqZw
            TGG4hk+mRkIhHqMoIflnL8e4wD0USDzKqWwE4HL86AHxLcu8WwNr1W8gyq/0jbzc
            qMSfDM60b0E14uHj6XHJVE848WUCgYEA9QfoI761baHO6QqLN9Nzyazz8igud+RS
            1OiHfQDtydYosfLGm9aajwHyNxwB+RPX1AxrE8TqV/Xn12nXa2p1S72WyoVn+lqM
            8K6NDg6eNTRsWal3a7Io2GQECNBrVU/b79bmIEca4XKXF3TgJKO1Slxtr3uQiBMr
            8/jDhUA+A4kCgYAmAB74d0elq4DhKo3bfRUOji1eQfmiFX1oegi47l138grd9Fnm
            9o2Q7hdw23hfH80M4VSKM0j3+Fjj6HRTgnoFZ2cQUMOtagCYc33I7B34vf7cy39m
            DzYaS/hjRZnKTV/eg4M9S8I7aFZxeaqCBifY5lkVPXhKuFSJJHfeN4FN+QKBgFRp
            SeZuf2/qKy6LDFTKCnxykYNdpkx1Irfn9yzwEfrTRSewXA05i/syD3A+vMtCs7qA
            IK8pyhVNSHYkJysA/LF/+Z+A/8X2RdFwQHWUQZpQmfb1c4dtU7bgFae3rRIxtbHV
            FWgPNsptwHE7OTBGGWEpoDuw1KSb/itJCoowDG0JAoGAY7LoaoyjCzPatUq4wa5q
            +ge5QauhBQdQ7omOAeJh/7LGugcZLMDjXeykpuI241xpVLTO9GM3DJMyVW4P+zTr
            JdWY3VcWzEwYLEXso6GDyAWBKURJdtrIsT1EC5XfzXdVHXA6XKzOuwL1NwAPRiEL
            /9iHbq5BkbD6Aw7VFUV4e4o=
            -----END PRIVATE KEY-----
            """;

    private static final String publicKeyX509String = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6qo5mEFbKV6ia+1y8TUS
            oH38NExvE7eyagBbD1BkM6W/+wzBqltTu0WD8oOUDz3wnRF9ahBAWRVacAYfHQSE
            oLJ75mVy0+iGThHwg1oL/ZQ51FqTK+GsGem/uu+EcZdjjIsFKOVHq5LJ3bTi3JZU
            DR+M0a0wMepg3MYMqzz/5lxxYCCUdxFZp2kmbCblxQJNOXZARdQPb514X82cvLRg
            HHNzFm2QGBX7+NFgYBekxc5ligyi/qdP1qKoJRRE/id9GT8t7mYg219rIGfFB7ky
            A0nKkZRprAX5BZ3nan0GGHoiDH8R1Qdr73TWOlj6DBoWEjtpHcobMwFax3+oxsNe
            DQIDAQAB
            -----END PUBLIC KEY-----
            """;

    @Test
    public void testCreateJwtWithStringParams() throws Exception {
        String issuer = "https://sso.myserver.com";
        String subject = "john.doe@myserver.com";
        String audience = "https://resources.myserver.com";
        int expiresIn = 500;
        String token = TokenGenerator.createJwt_RS256(issuer, subject, audience, expiresIn, privateKeyPkcs8String);
        System.out.println(token);
        printDecodedTokenParts(token);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509String);
        System.out.println("Token is valid: " + isValid);
        Assertions.assertTrue(isValid);
    }

    @Test
    public void testCreateJwtWithMapParams() throws Exception {
        Map<String, String> header = new HashMap<>();
        header.put("alg", "rsa256");
        header.put("typ", "JWT");

        Map<String, String> payload = new HashMap<>();
        payload.put("iss", "https://sso.myserver.com");
        payload.put("sub", "john.doe@myserver.com");
        payload.put("aud", "https://resources.myserver.com");
        payload.put("exp", String.valueOf(new Date().getTime() / 1000));

        String token = TokenGenerator.createJwt(header, payload, privateKeyPkcs8String);
        System.out.println(token);
        printDecodedTokenParts(token);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509String);
        System.out.println("Token is valid: " + isValid);
        Assertions.assertTrue(isValid);
    }

    private void printDecodedTokenParts(String token) {
        String[] parts = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        System.out.println("Header: " + new String(decoder.decode(parts[0]), StandardCharsets.UTF_8));
        System.out.println("Payload: " + new String(decoder.decode(parts[1]), StandardCharsets.UTF_8));
    }

}
