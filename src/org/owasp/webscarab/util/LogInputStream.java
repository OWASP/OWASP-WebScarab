/*
 * CopyInputStream.java
 *
 * Created on May 25, 2003, 10:59 AM
 */

package org.owasp.webscarab.util;

import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.PrintStream;

/**
 *
 * @author  rdawes
 */

public class LogInputStream extends FilterInputStream {
    InputStream _is;
    PrintStream _ps;
    
    public LogInputStream(InputStream is, PrintStream ps) {
        super(is);
        if (is == null) {
            throw new NullPointerException("InputStream may not be null!");
        }
        _is = is;
        _ps = ps;
    }
    
    public int read() throws IOException {
        int b = super.read();
        if (b > -1) {
            _ps.write(b);
            _ps.flush();
        }
        return b;
    }
    
    public int read(byte[] b, int off, int len) throws IOException {
        int num = super.read(b, off, len);
        if (num > 0) {
            _ps.write(b,off,num);
            _ps.flush();
        }
        return num;
    }

}

