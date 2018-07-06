package org.openeid.cdoc4j.crypto;

import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class PaddingUtilTest {

    private ByteArrayOutputStream outputStream;

    @Before
    public void init() {
        outputStream = new ByteArrayOutputStream();
    }

    @Test
    public void testX923PaddingAddition_padded12() throws IOException {
        String data = "test";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(12, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}, outputStream.toByteArray()));
    }

    @Test
    public void testX923PaddingAddition_padded4() throws IOException {
        String data = "testtesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(4, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4}, outputStream.toByteArray()));
    }

    @Test
    public void testX923PaddingAddition_padded16() throws IOException {
        String data = "testtesttesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addX923Padding(outputStream, data.length(), 16);
        assertSame(16, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}, outputStream.toByteArray()));
    }

    @Test
    public void testX923PaddingRemoval() {
        assertTrue(Arrays.equals("test".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12})));

        assertTrue(Arrays.equals("testtesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 4})));

        assertTrue(Arrays.equals("testtesttesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removeX923Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16})));
    }

    @Test
    public void testPkcs7PaddingAddition_padded12() throws IOException {
        String data = "test";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(12, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}, outputStream.toByteArray()));
    }

    @Test
    public void testPkcs7PaddingAddition_padded4() throws IOException {
        String data = "testtesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(4, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4}, outputStream.toByteArray()));
    }

    @Test
    public void testPkcs7PaddingAddition16() throws IOException {
        String data = "testtesttesttest";
        outputStream.write(data.getBytes());
        int paddedBytes = PaddingUtil.addPkcs7Padding(outputStream, data.length(), 16);
        assertSame(16, paddedBytes);
        assertTrue(Arrays.equals(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16},
                outputStream.toByteArray()));
    }

    @Test
    public void testPkcs7PaddingRemoval() {
        assertTrue(Arrays.equals("test".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12})));

        assertTrue(Arrays.equals("testtesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 4, 4, 4, 4})));

        assertTrue(Arrays.equals("testtesttesttest".getBytes(StandardCharsets.UTF_8),
                PaddingUtil.removePkcs7Padding(new byte[] {116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 116, 101, 115, 116, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16})));
    }
} 
