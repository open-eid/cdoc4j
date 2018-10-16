package org.openeid.cdoc4j;

import java.io.File;
/**
 * CDOC file system handler for non regular actions
 * Default handler is DefaultCDOCFileSystemHandler class
 */
public interface CDOCFileSystemHandler {
    /**
     * Handle issue of existing file in file system
     * <p>
     *
     * @param name of the file
     * @return file
     */
    File handleExistingFileIssue(File file);

}
