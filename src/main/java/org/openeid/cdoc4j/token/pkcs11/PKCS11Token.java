package org.openeid.cdoc4j.token.pkcs11;

import org.openeid.cdoc4j.ECRecipient;
import org.openeid.cdoc4j.RSARecipient;
import org.openeid.cdoc4j.crypto.CryptUtil;
import org.openeid.cdoc4j.exception.DecryptionException;
import org.openeid.cdoc4j.token.Token;
import org.openeid.cdoc4j.token.pkcs11.exception.PKCS11Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

public class PKCS11Token implements Token {

    private static final Logger LOGGER = LoggerFactory.getLogger(PKCS11Token.class);

    private static final String SUN_PKCS11_PROVIDERNAME = "SunPKCS11";

    private static final String SUN_PKCS11_CLASSNAME = "sun.security.pkcs11.SunPKCS11";

    private Provider pkcs11Provider;

    private KeyStore.PrivateKeyEntry keyEntry;

    private PKCS11TokenParams params;

    public PKCS11Token(PKCS11TokenParams params) throws PKCS11Exception {
        this.params = params;
        keyEntry = getKeyEntries().get(0);
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

    @Override
    protected void finalize() throws Throwable {
        if (pkcs11Provider != null) {
            try {
                Security.removeProvider(pkcs11Provider.getName());
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        super.finalize();
    }

    private List<KeyStore.PrivateKeyEntry> getKeyEntries() throws PKCS11Exception {
        List<KeyStore.PrivateKeyEntry> list = new ArrayList<>();
        try {
            KeyStore keystore = getKeyStore();
            if (params.getLabel() != null) {
                KeyStore.PrivateKeyEntry key = getKSPrivateKeyEntry(keystore, getKeyProtectionParameter(), params.getLabel());
                if (key != null) {
                    list.add(key);
                }
            } else {
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    KeyStore.PrivateKeyEntry key = getKSPrivateKeyEntry(keystore, getKeyProtectionParameter(), alias);
                    if (key != null) {
                        list.add(key);
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            String message = "Unable to retrieve keys from keystore";
            LOGGER.error(message, e);
            throw new PKCS11Exception(message, e);
        }
        return list;
    }

    KeyStore.ProtectionParameter getKeyProtectionParameter() {
        return null;
    }

    private KeyStore.PrivateKeyEntry getKSPrivateKeyEntry(KeyStore keystore, KeyStore.ProtectionParameter passwordProtection, String alias) throws GeneralSecurityException {
        if (keystore.isKeyEntry(alias)) {
            KeyStore.Entry entry = keystore.getEntry(alias, passwordProtection);
            if (entry instanceof KeyStore.PrivateKeyEntry) {
                KeyStore.PrivateKeyEntry pkentry = (KeyStore.PrivateKeyEntry) entry;
                return pkentry;
            }
        }
        return null;
    }

    private KeyStore getKeyStore() throws PKCS11Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", getProvider());
            keyStore.load(new KeyStore.LoadStoreParameter() {

                    @Override
                    public KeyStore.ProtectionParameter getProtectionParameter() {
                        return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                            @Override
                            public void handle(Callback[] callbacks) {
                                for (Callback c : callbacks) {
                                    if (c instanceof PasswordCallback) {
                                        PrefilledPasswordInputCallback callback = new PrefilledPasswordInputCallback(params.getPin());
                                        ((PasswordCallback) c).setPassword(callback.getPassword());
                                        return;
                                    }
                                }
                                throw new RuntimeException("No password callback existent!");
                            }
                        });
                    }
            });
            return keyStore;
        } catch (Exception e) {
            String message = "Can't initialize PKCS#11";
            LOGGER.error(message, e);
            throw new PKCS11Exception(message, e);
        }
    }

    private Provider getProvider() throws PKCS11Exception {
        try {
            if (pkcs11Provider == null) {
                // check if the provider already exists
                Provider[] providers = Security.getProviders();
                if (providers != null) {
                    for (Provider provider : providers) {
                        String providerInfo = provider.getInfo();
                        if (providerInfo.contains(params.getPkcs11Path())) {
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

    private void installProvider() throws PKCS11Exception {
        String config = buildConfig();
        LOGGER.debug("PKCS11 Config : \n{}", config);

        Provider provider;
        if (isJavaGreaterOrEquals9()) {
            provider = getProviderJavaGreaterOrEquals9(config);
        } else {
            provider = getProviderJavaLowerThan9(config);
        }

        pkcs11Provider = provider;
        Security.addProvider(pkcs11Provider);
    }

    private String buildConfig() {
        /*
         * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
         * loading of multiple pkcs11 libraries.
         *
         * CKA_TOKEN attribute setting is added in order for ECDH key agreement to work with the (OpenSC) driver.
         */
        String aPKCS11LibraryFileName = params.getPkcs11Path();
        aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

        String pkcs11Config = "name = SmartCard" + UUID.randomUUID().toString() + "\n"
                + "library = \"" + aPKCS11LibraryFileName + "\"\n"
                + "slotListIndex = " + params.getSlot() + "\n"
                + "attributes(*,CKO_SECRET_KEY,*) = {\n" + "  CKA_TOKEN = false\n" + "}" ;

        return pkcs11Config;
    }

    private boolean isJavaGreaterOrEquals9() {
        try {
            Provider provider = Security.getProvider(SUN_PKCS11_PROVIDERNAME);
            if (provider != null) {
                Method configureMethod = provider.getClass().getMethod("configure", String.class);
                return configureMethod != null;
            }
        } catch (NoSuchMethodException e) {
            // ignore
        }
        return false;
    }

    private Provider getProviderJavaGreaterOrEquals9(String configString) throws PKCS11Exception {
        try {
            Provider provider = Security.getProvider(SUN_PKCS11_PROVIDERNAME);
            Method configureMethod = provider.getClass().getMethod("configure", String.class);
            // "--" is permitted in the constructor sun.security.pkcs11.Config
            return (Provider) configureMethod.invoke(provider, "--" + configString);
        } catch (Exception e) {
            throw new PKCS11Exception("Unable to instantiate PKCS11 for JDK >= 9", e);
        }
    }

    private Provider getProviderJavaLowerThan9(String config) throws PKCS11Exception {
        try (ByteArrayInputStream configStream = new ByteArrayInputStream(config.getBytes())) {
            Class<?> sunPkcs11ProviderClass = Class.forName(SUN_PKCS11_CLASSNAME);
            Constructor<?> constructor = sunPkcs11ProviderClass.getConstructor(InputStream.class);
            return (Provider) constructor.newInstance(configStream);
        } catch (Exception e) {
            throw new PKCS11Exception("Unable to instantiate PKCS11 for JDK < 9 ", e);
        }
    }

    private String escapePath(String pathToEscape) {
        if (pathToEscape != null) {
            return pathToEscape.replace("\\", "\\\\");
        } else {
            return "";
        }
    }

}
