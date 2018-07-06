package org.openeid.cdoc4j.crypto;

import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;

public class KeyGenUtil {

    public static SecretKey generateDataEncryptionKey(int lengthInBytes) {
        final byte[] keyBytes = new byte[lengthInBytes];
        new SecureRandom().nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static KeyPair generateECKeyPair(ECPublicKey publicKey) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(publicKey.getParams());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyParameter generateGCMDataEncryptionKey(int lengthInBytes) {
        final byte[] keyBytes = new byte[lengthInBytes];
        new SecureRandom().nextBytes(keyBytes);
        return new KeyParameter(keyBytes);
    }
} 
