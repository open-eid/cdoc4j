package org.openeid.cdoc4j;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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

    public static DataFile mockDataFile(byte[] dataContent) {
        return new DataFile(UUID.randomUUID().toString() + "-test.txt", dataContent);
    }

    public static void assertFileDataFileContent(File decryptedDataFile, String expectedFileName, String expectedContent) throws IOException {
        assertFileDataFileContent(decryptedDataFile, expectedFileName, expectedContent.getBytes(StandardCharsets.UTF_8));
    }

    public static void assertFileDataFileContent(File decryptedDataFile, String expectedFileName, byte[] expectedContent) throws IOException {
        assertEquals(expectedFileName, decryptedDataFile.getName());
        assertEquals(expectedContent.length, decryptedDataFile.length());

        try (FileInputStream decryptedDataFileContent = new FileInputStream(decryptedDataFile)) {
            byte[] decryptedFileContent = new byte[decryptedDataFileContent.available()];
            decryptedDataFileContent.read(decryptedFileContent);

            assertTrue(Arrays.equals(expectedContent, decryptedFileContent));
        }
    }

    public static void deleteTestFile(List<File> dataFiles) {
        for (File file : dataFiles) {
            file.delete();
        }
    }
}
