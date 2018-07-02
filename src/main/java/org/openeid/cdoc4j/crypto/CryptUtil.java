package org.openeid.cdoc4j.crypto;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

public class CryptUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] encryptRsa(byte[] bytesToEncrypt, X509Certificate certificate) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());
        return cipher.doFinal(bytesToEncrypt);
    }

    public static byte[] decryptRsa(byte[] bytesToDecrypt, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(bytesToDecrypt);
    }

    public static void encryptAesCbc(OutputStream output, InputStream dataToEncrypt, SecretKey key, byte[] IV, int blockSize, long fileSize) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

        try (OutputStream cipherOutput = new BufferedOutputStream(new CipherOutputStream(output, cipher))) {
            IOUtils.copy(dataToEncrypt, cipherOutput, 1024);
            int paddedBytes = PaddingUtil.addX923Padding(cipherOutput, fileSize, blockSize);
            PaddingUtil.addPkcs7Padding(cipherOutput, fileSize + paddedBytes, blockSize);
        }
    }

    public static void encryptAesGcm(OutputStream output, InputStream dataToEncrypt, SecretKey key, byte[] IV) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec params = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        try (OutputStream cipherOutput = new CipherOutputStream(output, cipher)) {
            IOUtils.copy(dataToEncrypt, cipherOutput, 1024);
        }
    }

    public static byte[] generateIV(int blockSize) {
        byte[] iv = new byte[blockSize];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
} 
