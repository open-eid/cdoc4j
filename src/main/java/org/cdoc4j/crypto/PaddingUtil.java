package org.cdoc4j.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class PaddingUtil {

    private PaddingUtil() {}

    public static byte[] addX923Padding(byte[] bytesToPad, int blockSize) throws IOException {
        int padLength = blockSize - (bytesToPad.length % blockSize);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(bytesToPad);

        for (int i = 0; i < padLength - 1 ; i++) {
            outputStream.write(0x00);
        }
        outputStream.write((byte) padLength);
        return outputStream.toByteArray();
    }

    public static byte[] removeX923Padding(byte[] bytes) {
        int padLength = bytes[bytes.length - 1];

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(bytes, 0, bytes.length - padLength);
        return outputStream.toByteArray();
    }

    public static byte[] addPkcs7Padding(byte[] bytesToPad, int blockSize) throws IOException {
        int padLength = blockSize - (bytesToPad.length % blockSize);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(bytesToPad);

        for (int i = 0; i < padLength ; i++) {
            outputStream.write((byte) padLength);
        }
        return outputStream.toByteArray();
    }

    public static byte[] removePkcs7Padding(byte[] bytes) {
        int padLength = bytes[bytes.length - 1];

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(bytes, 0, bytes.length - padLength);
        return outputStream.toByteArray();
    }



} 
