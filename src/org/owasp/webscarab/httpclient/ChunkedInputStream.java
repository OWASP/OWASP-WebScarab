/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * ChunkedInputStream.java
 *
 * Created on May 25, 2003, 11:00 AM
 */

package org.owasp.webscarab.httpclient;

import java.util.ArrayList;
import java.util.logging.Logger;
import java.io.InputStream;
import java.io.FilterInputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ChunkedInputStream extends FilterInputStream {
    byte[] chunk = null;
    int start = 0;
    int size = 0;
    String[][] _trailer = null;
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    public ChunkedInputStream(InputStream in) throws IOException {
        super(in);
        readChunk();
    }
    
    public String[][] getTrailer() {
        return _trailer;
    }
    
    private void readChunk() throws IOException {
        String line = readLine().trim();
        try {
            size = Integer.parseInt(line.trim(),16);
            _logger.finest("Expecting a chunk of " + size + " bytes");
            chunk = new byte[size];
            int read = 0;
            while (read < size) {
                int got = in.read(chunk,read, Math.min(1024,size-read));
                _logger.finest("read " + got + " bytes");
                if (got>0) {
                    read = read + got;
                } else if (read == 0) {
                    _logger.info("read 0 bytes from the input stream! Huh!?");
                } else {
                    _logger.info("No more bytes to read from the stream, read " + read + " of " + size);
                    continue;
                }
            }
            _logger.finest("Got " + size + " bytes");
            if (size == 0) { // read the trailer and the CRLF
                readTrailer();
            } else {
                readLine(); // read the trailing line feed after the chunk body, but before the next chunk size
            }
            start = 0;
        } catch (NumberFormatException nfe) {
            _logger.severe("Error parsing chunk size from '" + line + "' : " + nfe);
        }
    }
    
    public int read() throws IOException {
        if (size == 0) {
            return -1;
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
            return -1;
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
    
    public int available() throws IOException {
        return size - start;
    }
    
    public boolean markSupported() {
        return false;
    }
    
    private String readLine() throws IOException {
        String line = new String();
        int i;
        byte[] b={(byte)0x00};
        i = in.read();
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a byte
            // we use an array because we can't concat a single byte :-(
            b[0] = (byte)(i & 0xFF);
            String input = new String(b,0,1);
            line = line.concat(input);
            i = in.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = in.read();
        }
        _logger.finest("Read '" + line + "'");
        return line;
    }
    
    private void readTrailer() throws IOException {
        String line = readLine();
        ArrayList trailer = new ArrayList();
        while (!line.equals("")) {
            String[] pair = line.split(": *",2);
            if (pair.length == 2) {
                trailer.add(pair);
            }
            line = readLine();
        }
        if (trailer.size()>0) {
            _trailer = new String[trailer.size()][2];
            for (int i=0; i<trailer.size(); i++) {
                String[] pair = (String[]) trailer.get(i);
                _trailer[i][0] = pair[0];
                _trailer[i][1] = pair[1];
            }
        }
    }
}
