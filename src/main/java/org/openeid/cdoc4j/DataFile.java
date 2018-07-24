package org.openeid.cdoc4j;

import java.io.*;

/**
 * Data file wrapper for handling files to be encrypted
 */
public class DataFile {

    private String name;
    private long size;
    private InputStream content;

    /**
     * Creates data file
     *
     * @param name of the file
     * @param content of the file
     * @param size of content
     */
    public DataFile(String name, InputStream content, long size) {
        this.name = name;
        this.content = content;
        this.size = size;
    }

    /**
     * Creates data file
     *
     * @param file
     */
    public DataFile(File file) throws FileNotFoundException {
        this.name = file.getName();
        this.content = new FileInputStream(file);
        this.size = file.length();
    }

    /**
     * Creates data file
     * <p>
     * Note that byte array isn't memory efficient in case of larger files.
     * For larger files it is recommended to use {@link #DataFile(File)} instead.
     *
     * @param name of the file
     * @param content of the file
     */
    public DataFile(String name, byte[] content) {
        this.name = name;
        this.content = new ByteArrayInputStream(content);
        this.size = content.length;
    }

    public String getName() {
        return name;
    }

    public long getSize() {
        return size;
    }

    public InputStream getContent() {
        return content;
    }
}
