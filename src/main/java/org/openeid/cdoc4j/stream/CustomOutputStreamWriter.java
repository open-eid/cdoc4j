package org.openeid.cdoc4j.stream;

import java.io.OutputStream;
import java.io.OutputStreamWriter;

public class CustomOutputStreamWriter extends OutputStreamWriter implements LastWriteInformable {

    private final OutputStream out;

    public CustomOutputStreamWriter(OutputStream out) {
        super(out);
        this.out = out;
    }

    @Override
    public void informOfLastWrite() {
        if (out instanceof LastWriteInformable) {
            ((LastWriteInformable) out).informOfLastWrite();
        }
    }
}
