/*
 * CopyInputStream.java
 *
 * Created on May 25, 2003, 10:59 AM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;

/**
 *
 * @author  rdawes
 */

public class CopyInputStream extends FilterInputStream {
    InputStream is;
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    public CopyInputStream(InputStream is) {
        super(is);
        this.is = is;
    }
    
    public int read() throws IOException {
        int b = is.read();
        if (b > -1) {
            baos.write(b);
        }
        return b;
    }
    
    public int read(byte[] b) throws IOException {
        return read(b,0,b.length);
    }
    
    public int read(byte[] b, int off, int len) throws IOException {
        int num = is.read(b, off, b.length);
        if (num > 0) {
            baos.write(b,off,num);
        }
        return num;
    }
    
    public byte[] toByteArray() {
        return baos.toByteArray();
    }
    
    public int available() throws IOException {
        return is.available();
    }
}

