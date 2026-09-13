package de.alexanderwolz.token;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MainTest extends AbstractTest {

    private final PrintStream originalOut = System.out;
    private ByteArrayOutputStream capturedOut;

    @BeforeEach
    public void captureStdOut() {
        capturedOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(capturedOut));
    }

    @AfterEach
    public void restoreStdOut() {
        System.setOut(originalOut);
    }

    @Test
    public void testPrintMenuOnMissingArgs() throws Exception {
        Main.main(new String[]{});
        Assertions.assertTrue(capturedOut.toString().contains("Usage:"));
    }

    @Test
    public void testCreateThenVerifyWithPublicKeyFile() throws Exception {
        String[] createArgs = {
                Main.FLAG_CREATE,
                privateKeyPkcs8File,
                "sso.server.com",
                "john.doe@server.com",
                "resource.server.com",
                "500"
        };
        Main.main(createArgs);
        String token = extractToken(capturedOut.toString());

        captureStdOut();
        Main.main(new String[]{Main.FLAG_VERIFY, publicKeyX509File, token});
        Assertions.assertTrue(capturedOut.toString().contains("Token signature is valid: true"));
    }

    @Test
    public void testCreateThenVerifyWithPublicKeyString() throws Exception {
        String[] createArgs = {
                Main.FLAG_CREATE,
                privateKeyPkcs8File,
                "sso.server.com",
                "john.doe@server.com",
                "resource.server.com",
                "500"
        };
        Main.main(createArgs);
        String token = extractToken(capturedOut.toString());
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(publicKeyX509File)));

        captureStdOut();
        Main.main(new String[]{Main.FLAG_VERIFY, publicKeyContent, token});
        Assertions.assertTrue(capturedOut.toString().contains("Token signature is valid: true"));
    }

    @Test
    public void testVerifyRejectsTamperedToken() throws Exception {
        String[] createArgs = {
                Main.FLAG_CREATE,
                privateKeyPkcs8File,
                "sso.server.com",
                "john.doe@server.com",
                "resource.server.com",
                "500"
        };
        Main.main(createArgs);
        String token = extractToken(capturedOut.toString());
        // Flip a character in the middle of the token to invalidate it.
        // Deliberately not the last character of a base64url segment: when a
        // segment's byte length isn't a multiple of 3, its last character
        // encodes trailing padding bits that some decoders (including
        // Java's) don't validate, so changing only that character can
        // decode to the exact same bytes and leave verification - and this
        // test - unchanged.
        int tamperIndex = token.length() / 2;
        char original = token.charAt(tamperIndex);
        char replacement = original == 'A' ? 'B' : 'A';
        String tamperedToken = token.substring(0, tamperIndex) + replacement + token.substring(tamperIndex + 1);

        captureStdOut();
        Main.main(new String[]{Main.FLAG_VERIFY, publicKeyX509File, tamperedToken});
        Assertions.assertTrue(capturedOut.toString().contains("Token signature is valid: false"));
    }

    private String extractToken(String output) {
        for (String line : output.split("\\R")) {
            if (line.startsWith("eyJ")) {
                return line.trim();
            }
        }
        throw new IllegalStateException("No token found in output:\n" + output);
    }

}
