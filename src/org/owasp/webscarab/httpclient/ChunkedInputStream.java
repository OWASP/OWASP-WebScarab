/*
 * ChunkedInputStream.java
 *
 * Created on May 25, 2003, 11:00 AM
 */

package org.owasp.webscarab.httpclient;

import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ChunkedInputStream extends FilterInputStream {
    InputStream _is;
    byte[] chunk = null;
    int start = 0;
    int size = 0;
    
    public ChunkedInputStream(InputStream is) throws IOException {
        super(is);
        // System.err.println("Creating ChunkedInputStream");
        _is = is;
        readChunk();
    }
    
    private void readChunk() throws IOException {
        try {
            size = Integer.parseInt(readLine(),16);
            // System.out.println("Expecting " + size);
            chunk = new byte[size];
            int read = 0;
            while (read < size) {
                int got = _is.read(chunk,read, size-read);
                if (got>0) {
                    read = read + got;
                } else if (read == 0) {
                    System.out.println("read 0 bytes from the input stream! Huh!?");
                } else {
                    System.out.println("No more bytes to read from the stream, read " + read + " of " + size);
                    continue;
                }
            }
            String crlf = readLine();
            // System.out.print("Got '" + crlf + "' as a crlf");
            // System.out.println("Got " + size);
            start = 0;
        } catch (NumberFormatException nfe) {
            System.err.println("Error reading chunk size " + nfe);
            System.err.println("Previous chunk was '" + new String(chunk) + "'");
        }
    }
    
    public int read() throws IOException {
        if (size == 0) {
            throw new IOException("Read called on a chunk size of 0");
        }
        if (start == size) {
            readChunk();
        }
        if (size == 0) {
            return -1;
        }
        return chunk[start++];
    }
    
    public int read(byte[] b) throws IOException {
        return read(b,0,b.length);
    }
    
    public int read(byte[] b, int off, int len) throws IOException {
        if (size == 0) {
            throw new IOException("Read called on a chunk size of 0");
        }
        if (start == size) {
            readChunk();
        }
        if (size == 0) {
            return -1;
        }
        if (len - off < available()) {
        } else {
            len = available();
        }
        System.arraycopy(chunk, start, b, off, len);
        start += len;
        return len;
    }
    
    public int available() {
        return size - start;
    }
    
    public boolean markSupported() {
        return false;
    }
    
    private String readLine() throws IOException {
        String line = new String();
        int i;
        byte[] b={(byte)0x00};
        i = _is.read();
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a byte
            // we use an array because we can't concat a single byte :-(
            b[0] = (byte)(i & 0xFF);
            String input = new String(b,0,1);
            line = line.concat(input);
            i = _is.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = _is.read();
        }
        // System.out.println("Read '" + line + "'");
        return line;
    }
    
}
