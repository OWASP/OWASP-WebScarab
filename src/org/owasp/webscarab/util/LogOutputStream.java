/*
 * CopyInputStream.java
 *
 * Created on May 25, 2003, 10:59 AM
 */

package org.owasp.webscarab.util;

import java.io.OutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.PrintStream;

/**
 *
 * @author  rdawes
 */

public class LogOutputStream extends FilterOutputStream {
    OutputStream _os;
    PrintStream _ps;
    
    public LogOutputStream(OutputStream os, PrintStream ps) {
        super(os);
        _os = os;
        _ps = ps;
    }
    
    public void write(int b) throws IOException {
        _os.write(b);
        _ps.write(b);
    }
    
    public void write(byte b[], int off, int len) throws IOException {
        _os.write(b, off, len);
        _ps.write(b, off, len);
    }
    
}

