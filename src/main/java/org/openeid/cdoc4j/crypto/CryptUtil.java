package org.openeid.cdoc4j.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
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

    public static byte[] encryptAesCbc(byte[] bytesToEncrypt, SecretKey key, byte[] iv) throws IOException, GeneralSecurityException {
        int blockSize = key.getEncoded().length;
        bytesToEncrypt = PaddingUtil.addX923Padding(bytesToEncrypt, blockSize);
        bytesToEncrypt = PaddingUtil.addPkcs7Padding(bytesToEncrypt, blockSize);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(bytesToEncrypt);
    }

    public static byte[] decryptAesCbc(byte[] bytesToDecrypt, SecretKey key, byte[] iv) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] decryptedBytes = cipher.doFinal(bytesToDecrypt);
        decryptedBytes = PaddingUtil.removePkcs7Padding(decryptedBytes);
        decryptedBytes = PaddingUtil.removeX923Padding(decryptedBytes);
        return decryptedBytes;
    }

    public static byte[] encryptAesGcm(byte[] bytesToEncrypt, SecretKey key, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec params = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        return cipher.doFinal(bytesToEncrypt);
    }

    public static byte[] decryptAesGcm(byte[] bytesToDecrypt, SecretKey key, byte[] iv) throws IOException, GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(bytesToDecrypt);
    }

    public static byte[] generateIV(int blockSize) {
        byte[] iv = new byte[blockSize];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

} 
