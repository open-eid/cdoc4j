package org.openeid.cdoc4j.stream;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public class DecryptionCipherOutputStream extends CipherOutputStream implements LastWriteInformable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DecryptionCipherOutputStream.class);

    private final int IVLength;
    private boolean freshStream;

    public DecryptionCipherOutputStream(OutputStream outputStream, AEADBlockCipher cipher, byte[] IV) {
        super(outputStream, cipher);
        this.IVLength = IV.length;
        this.freshStream = true;
    }

    public DecryptionCipherOutputStream(OutputStream outputStream, BufferedBlockCipher cipher, byte[] IV) {
        super(outputStream, cipher);
        this.IVLength = IV.length;
        this.freshStream = true;
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
        if (freshStream) {
            LOGGER.debug("First decryption stream write, removing IV");
            bytes = removeIVBytes(bytes);
            len = len - IVLength;
            freshStream = false;
        }

        super.write(bytes, off, len);
    }

    @Override
    public void informOfLastWrite() {
        if (out instanceof LastWriteInformable) {
            ((LastWriteInformable) out).informOfLastWrite();
        }
    }

    @Override
    public void close() throws IOException {
        super.close();
        /*
           Trigger PaddingRemovalOutputStream cached buffer write in case it was informed about the last write
           but no actual write was triggered through cipher or cipher stream closing process.
         */
        out.write(new byte[0], 0, 0);
    }

    private byte[] removeIVBytes(byte[] bytes) {
        return Arrays.copyOfRange(bytes, IVLength, bytes.length);
    }
}
