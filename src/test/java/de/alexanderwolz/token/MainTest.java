package de.alexanderwolz.token;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

public class MainTest extends AbstractTest {

    @Test
    public void testPrintMenu() throws Exception {
        String[] input = {};
        Main.main(input);
    }

    @Test
    public void testVerifyWithPublicKeyFile() throws Exception {
        String[] input = {Main.FLAG_VERIFY, publicKeyX509File, token};
        Main.main(input);
    }

    @Test
    public void testVerifyWithPublicKeyString() throws Exception {
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(publicKeyX509File)));
        String[] input = {Main.FLAG_VERIFY, publicKeyContent, token};
        Main.main(input);
    }

    @Test
    public void testCreate() throws Exception {
        String[] input = {
                Main.FLAG_CREATE,
                privateKeyPkcs8File,
                "sso.server.com",
                "john.doe@server.com",
                "resource.server.com",
                "500"
        };
        Main.main(input);
    }

}
