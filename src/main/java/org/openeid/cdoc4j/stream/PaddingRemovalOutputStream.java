package org.openeid.cdoc4j.stream;

import org.openeid.cdoc4j.crypto.PaddingUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public class PaddingRemovalOutputStream extends OutputStream implements LastWriteInformable {

    private final OutputStream outputStream;
    private byte[] cachedBuffer = new byte[0];
    private boolean isLastWrite = false;

    public PaddingRemovalOutputStream(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    /**
     * Removes X923 padding for the last write.
     * @param bytes
     * @param off
     * @param len
     * @throws IOException
     */
    @Override
    public void write(byte bytes[], int off, int len) throws IOException {
        if (isLastWrite) {
            byte[] finalBytes = Arrays.copyOfRange(bytes, off, len);
            if (isPreviousBufferCached()) {
                finalBytes = combineWithCachedBuffer(finalBytes);
            }
            finalBytes = PaddingUtil.removeX923Padding(finalBytes);
            outputStream.write(finalBytes);
            cachedBuffer = new byte[0];
            isLastWrite = false;
        } else {
            if (isPreviousBufferCached()) {
                outputStream.write(cachedBuffer);
            }
            cachedBuffer = Arrays.copyOfRange(bytes, off, len);
        }
    }

    @Override
    public void write(byte[] buffer) throws IOException {
        outputStream.write(buffer);
    }

    @Override
    public void write(int b) throws IOException {
        outputStream.write(b);
    }

    @Override
    public void informOfLastWrite() {
        isLastWrite = true;
    }

    private boolean isPreviousBufferCached() {
        return cachedBuffer.length > 0;
    }

    private byte[] combineWithCachedBuffer(byte[] currentBufferContent) {
        try (ByteArrayOutputStream concatStream = new ByteArrayOutputStream()) {
            concatStream.write(cachedBuffer);
            concatStream.write(currentBufferContent);
            return concatStream.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to concat cached buffer with latest write buffer", e);
        }
    }
}