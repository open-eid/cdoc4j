package org.openeid.cdoc4j;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestUtil {

    public static void assertStreamClosed(InputStream inputStream) {
        try {
            inputStream.read();
        } catch (IOException e) {
            assertTrue(e.getLocalizedMessage().equalsIgnoreCase("Stream closed"));
        }
    }

    public static DataFile mockDataFile(String dataContent) {
        return mockDataFile(dataContent.getBytes(StandardCharsets.UTF_8));
    }

    public static DataFile mockDataFile(byte[] dataContent) {
        return new DataFile("test.txt", dataContent);
    }

    public static void assertByteStreamDataFileContent(DataFile decryptedDataFile, String expectedFileName, String expectedContent) throws IOException {
        assertByteStreamDataFileContent(decryptedDataFile, expectedFileName, expectedContent.getBytes(StandardCharsets.UTF_8));
    }

    public static void assertByteStreamDataFileContent(DataFile decryptedDataFile, String expectedFileName, byte[] expectedContent) throws IOException {
        assertEquals(expectedFileName, decryptedDataFile.getName());
        assertEquals(expectedContent.length, decryptedDataFile.getSize());

        ByteArrayInputStream decryptedDataFileContent = (ByteArrayInputStream) decryptedDataFile.getContent();
        byte[] decryptedFileContent = new byte[decryptedDataFileContent.available()];
        decryptedDataFileContent.read(decryptedFileContent);

        assertTrue(Arrays.equals(expectedContent, decryptedFileContent));
    }

    public static void assertFileDataFileContent(DataFile decryptedDataFile, String expectedFileName, String expectedContent) throws IOException {
        assertFileDataFileContent(decryptedDataFile, expectedFileName, expectedContent.getBytes(StandardCharsets.UTF_8));
    }

    public static void assertFileDataFileContent(DataFile decryptedDataFile, String expectedFileName, byte[] expectedContent) throws IOException {
        assertEquals(expectedFileName, decryptedDataFile.getName());
        assertEquals(expectedContent.length, decryptedDataFile.getSize());

        FileInputStream decryptedDataFileContent = (FileInputStream) decryptedDataFile.getContent();
        byte[] decryptedFileContent = new byte[decryptedDataFileContent.available()];
        decryptedDataFileContent.read(decryptedFileContent);

        assertTrue(Arrays.equals(expectedContent, decryptedFileContent));
    }
}
