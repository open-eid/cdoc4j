package org.openeid.cdoc4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class DefaultCDOCFileSystemHandler implements CDOCFileSystemHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultCDOCFileSystemHandler.class);

    @Override
    public File onFileExists(File file) {
        file.delete();
        LOGGER.warn("Deleting {} file due to new File naming conflict", file);
        return file;
    }
}
