package org.openeid.cdoc4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class DefaultCDOCFileSystemHandler implements CDOCFileSystemHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultCDOCFileSystemHandler.class);

    @Override
    public File onFileExists(File existingFile) {
        existingFile.delete();
        LOGGER.warn("Deleting {} file due to new file naming conflict", existingFile);
        return existingFile;
    }
}
