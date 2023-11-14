package de.alexanderwolz.token;

public class Main {

    public static String FLAG_VERIFY = "-v";
    public static String FLAG_CREATE = "-c";

    public static void main(String[] args) throws Exception {
        try {
            if (args.length == 3 && FLAG_VERIFY.equals(args[0])) {
                TokenGenerator.printDecodedTokenParts(args[2]);
                System.out.println("Token signature is valid: " + TokenGenerator.verifyJwt_RS256(args[2], args[1]));
                return;
            }
            if (args.length == 6 && FLAG_CREATE.equals(args[0])) {
                String privateKey = args[1];
                String issuer = args[2];
                String subject = args[3];
                String audience = args[4];
                int expiresIn = Integer.parseInt(args[5]);
                String token = TokenGenerator.createJwt_RS256(issuer, subject, audience, expiresIn, privateKey);
                System.out.println("\n");
                TokenGenerator.printDecodedTokenParts(token);
                System.out.println("\n");
                System.out.println(token);
                System.out.println("\n");
                return;
            }
            printHelp();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static void printHelp() {
        System.out.println("\n" +
                "Usage:\n"
                + FLAG_VERIFY + " publicKey token\n"
                + FLAG_CREATE + " privateKey issuer subject audience expiresInSeconds\n");
    }
}
