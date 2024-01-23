package org.openeid.cdoc4j.crypto;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class PaddingUtilTest {

    @Test
    void testX923PaddingAddition_padded12() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "test";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(12, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12},
                outputStream.toByteArray());
    }

    @Test
    void testX923PaddingAddition_padded4() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "testtesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(4, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4},
                outputStream.toByteArray());
    }

    @Test
    void testX923PaddingAddition_padded16() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "testtesttesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(16, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16},
                outputStream.toByteArray());
    }

    @Test
    void testX923PaddingRemoval() {
        assertArrayEquals("test".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[]{116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}));

        assertArrayEquals("testtesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4}));

        assertArrayEquals("testtesttesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}));
    }

    @Test
    void testPkcs7PaddingAddition_padded12() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "test";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(12, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12},
                outputStream.toByteArray());
    }

    @Test
    void testPkcs7PaddingAddition_padded4() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "testtesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(4, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4},
                outputStream.toByteArray());
    }

    @Test
    void testPkcs7PaddingAddition16() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String data = "testtesttesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(16, paddedBytes);
        assertArrayEquals(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
                outputStream.toByteArray());
    }

    @Test
    void testPkcs7PaddingRemoval() {
        assertArrayEquals("test".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[]{116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}));

        assertArrayEquals("testtesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4}));

        assertArrayEquals("testtesttesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[]{116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}));
    }
} 
