package org.abstractj.example;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by abstractj on 5/22/14.
 */
public class KeyExtractor {

    private PrivateKeyInfo privateKeyInfo;
    private SubjectPublicKeyInfo publicKeyInfo;

    private JcaPEMKeyConverter pemKeyConverter = new JcaPEMKeyConverter();

    public KeyExtractor(File file, String passphrase) {

        try {
            PEMParser pemParser = new PEMParser(new FileReader(file));
            Object encryptedKeys = pemParser.readObject();

            if (encryptedKeys instanceof PEMEncryptedKeyPair) {
                PEMDecryptorProvider pemDecryptor = new JcePEMDecryptorProviderBuilder().build(passphrase.toCharArray());
                PEMKeyPair rawKeyPair = ((PEMEncryptedKeyPair) encryptedKeys).decryptKeyPair(pemDecryptor);

                privateKeyInfo = rawKeyPair.getPrivateKeyInfo();
                publicKeyInfo = rawKeyPair.getPublicKeyInfo();
            }

            pemParser.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PrivateKey getPrivateKey() throws PEMException {
        return pemKeyConverter.getPrivateKey(privateKeyInfo);
    }

    public PublicKey getPublicKey() throws PEMException {
        return pemKeyConverter.getPublicKey(publicKeyInfo);

    }

}
