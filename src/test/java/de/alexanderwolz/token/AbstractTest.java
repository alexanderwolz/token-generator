package de.alexanderwolz.token;

import java.io.File;

public abstract class AbstractTest {
    protected final String publicKeyX509File = new File("src/test/resources/public.pem").getAbsolutePath();
    protected final String privateKeyPkcs8File = new File("src/test/resources/private-pkcs8.pem").getAbsolutePath();
    protected final String privateKeyPkcs1File = new File("src/test/resources/private.pem").getAbsolutePath();

}
