/*
 * ChunkedInputStream.java
 *
 * Created on May 25, 2003, 11:00 AM
 */

package org.owasp.webscarab.httpclient;

import java.io.OutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ChunkedOutputStream extends FilterOutputStream {
    String[][] _trailer = null;
    boolean _writeTrailer = true;
    
    public ChunkedOutputStream(OutputStream out) throws IOException {
        super(out);
    }

    public void setTrailer(String[][] trailer) {
        _trailer = trailer;
    }
    
    public void writeTrailer() throws IOException {
        if (!_writeTrailer) return; // we've already written it
        out.write("0\r\n".getBytes());
        if (_trailer != null) {
            for (int i=0; i<_trailer.length; i++) {
                if (_trailer[i].length == 2) {
                    out.write((_trailer[i][0] + ": " + _trailer[i][1] + "\r\n").getBytes());
                }
            }
        }
        out.write("\r\n".getBytes());
        _writeTrailer = false;
    }
    
    public void write(int b) throws IOException {
        out.write("1\r\n".getBytes());
        out.write(b);
        out.write("\r\n".getBytes());
    }
    
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }
    
    public void write(byte[] b, int off, int len) throws IOException {
        out.write((Integer.toString(len - off, 16) + "\r\n").getBytes());
        out.write(b, off, len);
        out.write("\r\n".getBytes());
    }
    
}
