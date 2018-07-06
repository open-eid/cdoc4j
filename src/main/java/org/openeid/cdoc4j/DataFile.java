package org.openeid.cdoc4j;

import java.io.*;

public class DataFile {

    private String name;
    private long size;
    private InputStream file;

    public DataFile(String name, InputStream file, long size) {
        this.name = name;
        this.file = file;
        this.size = size;
    }

    public DataFile(File file) throws FileNotFoundException {
        this.name = file.getName();
        this.file = new FileInputStream(file);
        this.size = file.length();
    }

    public DataFile(String name, ByteArrayInputStream file) {
        this.name = name;
        this.file = file;
        this.size = file.available();
    }

    public DataFile(String name, byte[] content) {
        this.name = name;
        this.file = new ByteArrayInputStream(content);
        this.size = content.length;
    }

    public String getName() {
        return name;
    }

    public long getSize() {
        return size;
    }

    public InputStream getContent() {
        return file;
    }
}
