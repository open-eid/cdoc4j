package org.openeid.cdoc4j.crypto;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public final class PaddingUtil {

    private PaddingUtil() {}


    public static int addX923Padding(OutputStream dataStream, long fileSize, int blockSize) throws IOException {
        int padLength = (int) (blockSize - (fileSize % blockSize));

        for (int i = 0; i < padLength - 1 ; i++) {
            dataStream.write(0x00);
        }
        dataStream.write((byte) padLength);

        return padLength;
    }

    public static byte[] removeX923Padding(byte[] bytes) {
        int padLength = bytes[bytes.length - 1];
        return Arrays.copyOfRange(bytes, 0, bytes.length - padLength);
    }

    public static int addPkcs7Padding(OutputStream dataStream, long fileSize, int blockSize) throws IOException {
        int padLength = (int) (blockSize - (fileSize % blockSize));

        for (int i = 0; i < padLength ; i++) {
            dataStream.write((byte) padLength);
        }

        return padLength;
    }

    public static byte[] removePkcs7Padding(byte[] bytes) {
        int padLength = bytes[bytes.length - 1];
        return Arrays.copyOfRange(bytes, 0, bytes.length - padLength);
    }

} 
