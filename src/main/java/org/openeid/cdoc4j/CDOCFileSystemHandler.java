package org.openeid.cdoc4j;

import java.io.File;
/**
 * CDOC file system handler for non regular actions.
 * <p>
 * Default handler is DefaultCDOCFileSystemHandler class
 */
public interface CDOCFileSystemHandler {

    /**
     * Handle issue of existing file in file system
     * <p>
     *
     * @param existingFile
     * @return resolved destination file
     */
    File onFileExists(File existingFile);

}
