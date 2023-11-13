package de.alexanderwolz.token;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenGeneratorTest {

    //openssl genrsa -out private.pem 2048
    //openssl rsa -in private.pem -pubout -out public.pem
    //openssl pkcs8 -in private.pem -topk8 -nocrypt -out private-pkcs8.pem
    //First key is PKCS1 but Java only knows PKCS8, so we need to create one using OpenSSL

    private static String privateKeyPkcs8String = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqqjmYQVspXqJr\n" +
            "7XLxNRKgffw0TG8Tt7JqAFsPUGQzpb/7DMGqW1O7RYPyg5QPPfCdEX1qEEBZFVpw\n" +
            "Bh8dBISgsnvmZXLT6IZOEfCDWgv9lDnUWpMr4awZ6b+674Rxl2OMiwUo5Uerksnd\n" +
            "tOLcllQNH4zRrTAx6mDcxgyrPP/mXHFgIJR3EVmnaSZsJuXFAk05dkBF1A9vnXhf\n" +
            "zZy8tGAcc3MWbZAYFfv40WBgF6TFzmWKDKL+p0/WoqglFET+J30ZPy3uZiDbX2sg\n" +
            "Z8UHuTIDScqRlGmsBfkFnedqfQYYeiIMfxHVB2vvdNY6WPoMGhYSO2kdyhszAVrH\n" +
            "f6jGw14NAgMBAAECggEBAJeVSgr9/MMmbEjHY35ISDX/69Bkp0PXX5p1jFzCE1gB\n" +
            "c5fZz6gZwmawKuGW+Sc3XZw4VgkTYl2pG3hNm/+EkZ+0a7CSS7By/X6ku/Y9To2J\n" +
            "GCoCMBsidadvhPheC/HMVvPMQZL/OGKuOVPLqtfPC5BGlxJCi2VS/yrdjAV5K9xD\n" +
            "EhpfbNo33M+ZKyP0Ry1PbCsYkHL7jtyx5hfTaITcLbBHS32ZIJYscVrqLLxZufGx\n" +
            "4QkocAOXbqhNahn5YCOuIT1qiCY4lQItLWTxS50s1e9eP7UbQ58015DEt83hAnwT\n" +
            "7oxs80M5XjYhVBk5uOQ5sm1ZuuAcH9aDjfViq1QPOcECgYEA9SuF1h7zX2SEx69U\n" +
            "YHIgpwSvhDEw8YMWRw4Xw7G7tf7CqKF9Via5K31c99uJ61a/wKb4+2iq2XlxqqZw\n" +
            "TGG4hk+mRkIhHqMoIflnL8e4wD0USDzKqWwE4HL86AHxLcu8WwNr1W8gyq/0jbzc\n" +
            "qMSfDM60b0E14uHj6XHJVE848WUCgYEA9QfoI761baHO6QqLN9Nzyazz8igud+RS\n" +
            "1OiHfQDtydYosfLGm9aajwHyNxwB+RPX1AxrE8TqV/Xn12nXa2p1S72WyoVn+lqM\n" +
            "8K6NDg6eNTRsWal3a7Io2GQECNBrVU/b79bmIEca4XKXF3TgJKO1Slxtr3uQiBMr\n" +
            "8/jDhUA+A4kCgYAmAB74d0elq4DhKo3bfRUOji1eQfmiFX1oegi47l138grd9Fnm\n" +
            "9o2Q7hdw23hfH80M4VSKM0j3+Fjj6HRTgnoFZ2cQUMOtagCYc33I7B34vf7cy39m\n" +
            "DzYaS/hjRZnKTV/eg4M9S8I7aFZxeaqCBifY5lkVPXhKuFSJJHfeN4FN+QKBgFRp\n" +
            "SeZuf2/qKy6LDFTKCnxykYNdpkx1Irfn9yzwEfrTRSewXA05i/syD3A+vMtCs7qA\n" +
            "IK8pyhVNSHYkJysA/LF/+Z+A/8X2RdFwQHWUQZpQmfb1c4dtU7bgFae3rRIxtbHV\n" +
            "FWgPNsptwHE7OTBGGWEpoDuw1KSb/itJCoowDG0JAoGAY7LoaoyjCzPatUq4wa5q\n" +
            "+ge5QauhBQdQ7omOAeJh/7LGugcZLMDjXeykpuI241xpVLTO9GM3DJMyVW4P+zTr\n" +
            "JdWY3VcWzEwYLEXso6GDyAWBKURJdtrIsT1EC5XfzXdVHXA6XKzOuwL1NwAPRiEL\n" +
            "/9iHbq5BkbD6Aw7VFUV4e4o=\n" +
            "-----END PRIVATE KEY-----\n";

    private static String publicKeyX509String = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6qo5mEFbKV6ia+1y8TUS\n" +
            "oH38NExvE7eyagBbD1BkM6W/+wzBqltTu0WD8oOUDz3wnRF9ahBAWRVacAYfHQSE\n" +
            "oLJ75mVy0+iGThHwg1oL/ZQ51FqTK+GsGem/uu+EcZdjjIsFKOVHq5LJ3bTi3JZU\n" +
            "DR+M0a0wMepg3MYMqzz/5lxxYCCUdxFZp2kmbCblxQJNOXZARdQPb514X82cvLRg\n" +
            "HHNzFm2QGBX7+NFgYBekxc5ligyi/qdP1qKoJRRE/id9GT8t7mYg219rIGfFB7ky\n" +
            "A0nKkZRprAX5BZ3nan0GGHoiDH8R1Qdr73TWOlj6DBoWEjtpHcobMwFax3+oxsNe\n" +
            "DQIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    @Test
    public void testCreateJwtWithStringParams() throws Exception {
        String issuer = "https://sso.myserver.com";
        String subject = "john.doe@myserver.com";
        String audience = "https://resources.myserver.com";
        int expiresIn = 500;
        String token = TokenGenerator.createJwt_RS256(issuer, subject, audience, expiresIn, privateKeyPkcs8String);
        System.out.println(token);
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

        String token = TokenGenerator.createJwt_RS256(header, payload, privateKeyPkcs8String);
        System.out.println(token);
        boolean isValid = TokenGenerator.verifyJwt_RS256(token, publicKeyX509String);
        System.out.println("Token is valid: " + isValid);
        Assertions.assertTrue(isValid);
    }

}
