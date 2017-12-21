package org.cdoc4j.pkcs11;

import org.cdoc4j.pkcs11.exception.IncorrectPinException;
import org.cdoc4j.pkcs11.exception.PKCS11Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import java.io.ByteArrayInputStream;
import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

public class PKCS11Token {

    private static final Logger LOGGER = LoggerFactory.getLogger(PKCS11Token.class);

    private Provider pkcs11Provider;

    private final String pkcs11Path;

    private KeyStore keyStore;

    private final PrefilledPasswordInputCallback callback;

    private int slotIndex;

    public PKCS11Token(String pkcs11Path, PrefilledPasswordInputCallback callback, int slotIndex) {
        this.pkcs11Path = pkcs11Path;
        this.callback = callback;
        this.slotIndex = slotIndex;
    }

    public PKCS11Token(String pkcs11Path, char[] password, int slotIndex) {
        this(pkcs11Path, new PrefilledPasswordInputCallback(password), slotIndex);
    }

    public void removeProvider() {
        if (pkcs11Provider != null) {
            try {
                Security.removeProvider(pkcs11Provider.getName());
            } catch (Exception ex) {
                LOGGER.error(ex.getMessage(), ex);
            }
        }
    }

    public List<KeyStore.PrivateKeyEntry> getKeys() throws PKCS11Exception {
        final List<KeyStore.PrivateKeyEntry> list = new ArrayList<>();
        try {
            KeyStore keyStore = getKeyStore();
            final Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                final String alias = aliases.nextElement();
                list.add(getKSPrivateKeyEntry(alias, getKeyProtectionParameter()));
            }
        } catch (GeneralSecurityException e) {
            String message = "Unable to retrieve keys from keystore";
            LOGGER.error(message, e);
            throw new PKCS11Exception(message, e);
        }
        return list;
    }

    private Provider getProvider() throws PKCS11Exception {
        try {
            if (pkcs11Provider == null) {
                // check if the provider already exists
                final Provider[] providers = Security.getProviders();
                if (providers != null) {
                    for (final Provider provider : providers) {
                        final String providerInfo = provider.getInfo();
                        if (providerInfo.contains(pkcs11Path)) {
                            pkcs11Provider = provider;
                            return provider;
                        }
                    }
                }
                // provider not already installed

                installProvider();
            }
            return pkcs11Provider;
        } catch (ProviderException e) {
            String message = "Not a PKCS#11 library";
            LOGGER.error(message, e);
            throw new PKCS11Exception(message, e);
        }
    }

    private void installProvider() {
        /*
         * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
         * loading of multiple pkcs11 libraries.
         *
         * CKA_TOKEN attribute setting is added in order for ECDH key agreement to work with the (OpenSC) driver.
         */
        String aPKCS11LibraryFileName = pkcs11Path;
        aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

        String pkcs11ConfigSettings = "name = SmartCard" + UUID.randomUUID().toString() + "\n"
                + "library = \"" + aPKCS11LibraryFileName + "\"\n"
                + "slotListIndex = " + slotIndex + "\n"
                + "attributes(*,CKO_SECRET_KEY,*) = {\n" + "  CKA_TOKEN = false\n" + "}" ;

        byte[] pkcs11ConfigBytes = pkcs11ConfigSettings.getBytes();
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigBytes);

        sun.security.pkcs11.SunPKCS11 pkcs11 = new sun.security.pkcs11.SunPKCS11(confStream);
        pkcs11Provider = pkcs11;

        Security.addProvider(pkcs11Provider);
    }

    private String escapePath(String pathToEscape) {
        if (pathToEscape != null) {
            return pathToEscape.replace("\\", "\\\\");
        } else {
            return "";
        }
    }

    private KeyStore getKeyStore() throws PKCS11Exception {

        if (keyStore == null) {
            try {
                keyStore = KeyStore.getInstance("PKCS11", getProvider());
                keyStore.load(new KeyStore.LoadStoreParameter() {

                    @Override
                    public KeyStore.ProtectionParameter getProtectionParameter() {
                        return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                            @Override
                            public void handle(Callback[] callbacks) {
                                for (Callback c : callbacks) {
                                    if (c instanceof PasswordCallback) {
                                        ((PasswordCallback) c).setPassword(callback.getPassword());
                                        return;
                                    }
                                }
                                throw new RuntimeException("No password callback existent!");
                            }
                        });
                    }
                });
            } catch (Exception e) {
                if (e instanceof sun.security.pkcs11.wrapper.PKCS11Exception) {
                    if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
                        String message = "Incorrect PIN for PKCS#11";
                        LOGGER.error(message, e);
                        throw new IncorrectPinException(message, e);
                    }
                }
                String message = "Can't initialize Sun PKCS#11 security provider";
                LOGGER.error(message, e);
                throw new PKCS11Exception(message, e);
            }
        }
        return keyStore;
    }

    KeyStore.ProtectionParameter getKeyProtectionParameter() {
        return null;
    }

    private KeyStore.PrivateKeyEntry getKSPrivateKeyEntry(final String alias, KeyStore.ProtectionParameter passwordProtection) throws PKCS11Exception {
        KeyStore keyStore = getKeyStore();
        try {
            if (keyStore.isKeyEntry(alias)) {
                final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, passwordProtection);
                return entry;
            }
        } catch (GeneralSecurityException e) {
            String message = "Unable to retrieve key for alias '" + alias + "'";
            LOGGER.error(message, e);
            throw new PKCS11Exception(message, e);
        }
        return null;
    }

}
