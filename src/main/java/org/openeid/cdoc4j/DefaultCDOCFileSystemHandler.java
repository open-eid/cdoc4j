package org.openeid.cdoc4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class DefaultCDOCFileSystemHandler implements CDOCFileSystemHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultCDOCFileSystemHandler.class);

    @Override
    public File handleExistingFileIssue(File file) {
        LOGGER.info("Using default DefaultCDOCFileSystemHandler");
        file.delete();
        LOGGER.error("Deleting {} file", file);
        return file;
    }
}
