package org.openeid.cdoc4j.token.pkcs12;

import org.openeid.cdoc4j.ECRecipient;
import org.openeid.cdoc4j.RSARecipient;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.token.pkcs11.PKCS11Token;
import org.openeid.cdoc4j.token.pkcs12.exception.PKCS12Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class PKCS12Token implements Token {

    private static final Logger LOGGER = LoggerFactory.getLogger(PKCS11Token.class);

    private KeyStore.PrivateKeyEntry keyEntry;

    public PKCS12Token(InputStream p12InputStream, String password, String alias) throws PKCS12Exception {
        try {
            KeyStore p12 = KeyStore.getInstance("pkcs12");
            p12.load(p12InputStream, password.toCharArray());
            if (alias != null) {
                this.keyEntry = getKeyEntry(p12, password, alias);
            } else {
                Enumeration<String> aliases = p12.aliases();
                while (aliases.hasMoreElements()) {
                    String currentAlias = aliases.nextElement();
                    KeyStore.PrivateKeyEntry entry = getKeyEntry(p12, password, currentAlias);
                    if (entry != null) {
                        this.keyEntry = entry;
                        break;
                    }

                }
            }
        } catch (GeneralSecurityException | IOException e) {
            String message = "Error initializing PKCS#12 token";
            LOGGER.error(message, e);
            throw new PKCS12Exception(message, e);
        }
    }

    public PKCS12Token(InputStream p12InputStream, String password) throws PKCS12Exception {
        this(p12InputStream, password, null);
    }

    private KeyStore.PrivateKeyEntry getKeyEntry(KeyStore keystore, String password, String alias) throws GeneralSecurityException {
        if (keystore.isKeyEntry(alias)) {
            KeyStore.Entry entry = keystore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                return (KeyStore.PrivateKeyEntry) entry;
            }
        }
        return null;
    }

    @Override
    public Certificate getCertificate() {
        return keyEntry.getCertificate();
    }

    @Override
    public byte[] decrypt(RSARecipient recipient) throws DecryptionException {
        try {
            return CryptUtil.decryptRsa(recipient.getEncryptedKey(), keyEntry.getPrivateKey());
        } catch (GeneralSecurityException e) {
            String message = "Error decrypting secret key!";
            LOGGER.error(message, e);
            throw new DecryptionException(message, e);
        }
    }

    @Override
    public byte[] decrypt(ECRecipient recipient) throws DecryptionException {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(keyEntry.getPrivateKey());
            keyAgreement.doPhase(recipient.getEphemeralPublicKey(), true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            String message = "Error decrypting secret key!";
            LOGGER.error(message, e);
            throw new DecryptionException(message, e);
        }
    }

}
