package org.owasp.webscarab.ui.swing;

import java.io.OutputStream;
import java.io.IOException;

class TeeOutputStream extends OutputStream {

    OutputStream[] _streams;

    public TeeOutputStream(OutputStream[] streams) {
        _streams = streams;
    }

    public void write(int b) throws IOException {
        for (int i=0; i<_streams.length; i++) {
            _streams[i].write(b);
        }
    }

    public void write(byte[] buf, int off, int len) throws IOException {
        for (int i=0; i<_streams.length; i++) {
            _streams[i].write(buf, off, len);
        }
    }

    public void flush() throws IOException {
        for (int i=0; i<_streams.length; i++) {
            _streams[i].flush();
        }
    }

    public void close() throws IOException {
        for (int i=0; i<_streams.length; i++) {
            _streams[i].close();
        }
    }


}