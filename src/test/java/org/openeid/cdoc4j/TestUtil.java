package org.openeid.cdoc4j;

import org.apache.commons.io.IOUtils;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class TestUtil {

    public static void assertStreamClosed(InputStream inputStream) {
        try {
            assertTrue(inputStream.read() == -1);
        } catch (IOException e) {
            assertTrue(e.getLocalizedMessage().equalsIgnoreCase("Stream closed"));
        }
    }

    public static void assertStreamClosed(FileInputStream inputStream) {
        try {
            inputStream.read();
            fail("Stream expected to be closed!");
        } catch (IOException e) {
            assertTrue(e.getLocalizedMessage().equalsIgnoreCase("Stream closed"));
        }
    }

    public static DataFile mockDataFile(String dataContent) {
        return mockDataFile(dataContent.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] convertInputStreamToBytes(InputStream inputStream, long size) throws IOException {
        byte[] bytes = new byte[(int)size];
        inputStream.read(bytes, 0, (int)size);
        inputStream.close();
        return bytes;
    }

    public static DataFile mockDataFile(byte[] dataContent) {
        return new DataFile(UUID.randomUUID().toString() + "-test.txt", dataContent);
    }

    public static void assertDataFileContent(DataFile dataFile, String expectedFileName, String expectedContent) throws IOException {
        assertEquals(expectedFileName, dataFile.getName());
        byte[] bytes = convertInputStreamToBytes(dataFile.getContent(), dataFile.getSize());
        assertEquals(expectedContent, new String(bytes, StandardCharsets.UTF_8));
        assertEquals("application/octet-stream", dataFile.getMimeType());
        assertStreamClosed(dataFile.getContent());
    }

    public static void assertFileDataFileContent(File decryptedDataFile, String expectedFileName, String expectedContent) throws IOException {
        byte[] expectedContentBytes = expectedContent.getBytes();
        assertEquals(expectedFileName, decryptedDataFile.getName());
        assertEquals(expectedContentBytes.length, decryptedDataFile.length());

        try (FileInputStream decryptedDataFileContent = new FileInputStream(decryptedDataFile)) {
            byte[] decryptedFileContent = new byte[decryptedDataFileContent.available()];
            decryptedDataFileContent.read(decryptedFileContent);
            assertTrue(Arrays.equals(expectedContentBytes, decryptedFileContent));
        }
    }

    public static void assertFileDataFileContent(DataFile decryptedDataFile, String expectedFileName, byte[] expectedContent) throws IOException {
        assertEquals(expectedFileName, decryptedDataFile.getName());
        assertEquals(expectedContent.length, decryptedDataFile.getContent().available());

        byte[] decryptedFileContent = IOUtils.toByteArray(decryptedDataFile.getContent());
        assertTrue(Arrays.equals(expectedContent, decryptedFileContent));
    }

    public static void deleteTestFiles(List<File> dataFiles) {
        for (File file : dataFiles) {
            file.delete();
        }
    }

    public static void closeInMemoryStreams(List<DataFile> dataFiles) {
        for (DataFile dataFile : dataFiles) {
            IOUtils.closeQuietly(dataFile.getContent());
        }
    }
}
