package org.abstractj.example;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.File;

import static org.junit.Assert.assertEquals;

public class KeyExtractorTest {

    private String data = "My bonnie lies over the ocean";
    private KeyExtractor keyExtractor;

    @Before
    public void setUp() throws Exception {
        keyExtractor = new KeyExtractor(new File("src/main/resources/private.pem"), "12345678");
    }

    @Test
    public void testEncryption() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyExtractor.getPublicKey());
        byte[] cipherText = cipher.doFinal(data.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, keyExtractor.getPrivateKey());
        byte[] plainText = cipher.doFinal(cipherText);

        assertEquals("Decryption has failed, find someone to blame", data, new String(plainText, "UTF-8"));

    }

}