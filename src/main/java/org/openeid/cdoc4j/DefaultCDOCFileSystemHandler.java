package org.openeid.cdoc4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class DefaultCDOCFileSystemHandler implements CDOCFileSystemHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultCDOCFileSystemHandler.class);

    @Override
    public File onFileExists(File existingFile) {
        String existingFileName = existingFile.getName();
        int extensionIndex = existingFileName.lastIndexOf(".");
        long index = 1;
        while (true) {
            String newFileName;
            if (extensionIndex < 1) {
                newFileName = existingFileName + "_" + index++;
            } else {
                newFileName = existingFileName.substring(0, extensionIndex) + "_" + index++ + existingFileName.substring(extensionIndex);
            }
            File newFile = new File(existingFile.getParentFile(), newFileName);
            if (newFile.exists()) {
                LOGGER.warn("File {} already exists", newFile.getAbsolutePath());
            } else {
                LOGGER.info("File saved as {}", newFile.getAbsolutePath());
                return newFile;
            }
        }
    }
}
