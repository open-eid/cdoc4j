package org.cdoc4j;

public class DataFile {

    private String fileName;
    private byte[] content;

    public DataFile(String fileName, byte[] content) {
        this.fileName = fileName;
        this.content = content;
    }

    public byte[] getContent() {
        return content;
    }

    public String getFileName() {
        return fileName;
    }

}
