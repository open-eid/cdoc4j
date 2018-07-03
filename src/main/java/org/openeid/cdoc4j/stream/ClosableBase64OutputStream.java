package org.openeid.cdoc4j.stream;


import org.openeid.cdoc4j.stream.base64.Base64OutputStream;

import java.io.IOException;
import java.io.OutputStream;

public class ClosableBase64OutputStream extends Base64OutputStream implements LastWriteInformable {

    public ClosableBase64OutputStream(OutputStream out) {
        super(out);
    }

    public ClosableBase64OutputStream(OutputStream out, boolean doEncode) {
        super(out, doEncode);
    }

    // Closes current stream without closing the wrapped output stream
    @Override
    public void close() throws IOException {
        eof();
        flush();
    }

    @Override
    public void informOfLastWrite() {
        if (out instanceof LastWriteInformable) {
            ((LastWriteInformable) out).informOfLastWrite();
        }
    }
}
