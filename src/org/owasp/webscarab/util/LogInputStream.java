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
 * This class can be used to create a copy of the bytes that are read from the
 * supplied InputStream
 * @author rdawes
 */

public class LogInputStream extends FilterInputStream {
    private PrintStream _ps;
    
    /**
     * This class can be used to keep a copy of the bytes read from the supplied
     * InputStream
     * @param is The InputStream to read from
     * @param ps the PrintStream to write any bytes read to. We use a PrintStream so that we don't have to worry about any Exceptions on the OutputStream
     */    
    public LogInputStream(InputStream is, PrintStream ps) {
        super(is);
        if (is == null) {
            throw new NullPointerException("InputStream may not be null!");
        }
        _ps = ps;
    }
    
    /**
     * Reads the next byte of data from this input stream. The value
     * byte is returned as an <code>int</code> in the range
     * <code>0</code> to <code>255</code>. If no byte is available
     * because the end of the stream has been reached, the value
     * <code>-1</code> is returned. This method blocks until input data
     * is available, the end of the stream is detected, or an exception
     * is thrown.
     * <p>
     * This method
     * simply performs <code>in.read()</code> and returns the result.
     *
     * @return     the next byte of data, or <code>-1</code> if the end of the
     *             stream is reached.
     * @exception  IOException  if an I/O error occurs.
     * @see        java.io.FilterInputStream#in
     */
    public int read() throws IOException {
        int b = super.read();
        if (b > -1) {
            _ps.write(b);
            _ps.flush();
        } else {
            // we close to signal downstream readers that the inputstream has closed
            _ps.close();
        }
        return b;
    }
    
    /**
     * Reads up to <code>len</code> bytes of data from this input stream
     * into an array of bytes. This method blocks until some input is
     * available.
     * <p>
     * This method simply performs <code>in.read(b, off, len)</code>
     * and returns the result.
     *
     * @param      b     the buffer into which the data is read.
     * @param      off   the start offset of the data.
     * @param      len   the maximum number of bytes read.
     * @return     the total number of bytes read into the buffer, or
     *             <code>-1</code> if there is no more data because the end of
     *             the stream has been reached.
     * @exception  IOException  if an I/O error occurs.
     * @see        java.io.FilterInputStream#in
     */
    public int read(byte[] b, int off, int len) throws IOException {
        int num = super.read(b, off, len);
        if (num > 0) {
            _ps.write(b,off,num);
            _ps.flush();
        } else {
            _ps.close();
        }
        return num;
    }

    /**
     * Tests if this input stream supports the <code>mark</code>
     * and <code>reset</code> methods.
     * This method always returns false, as we are not able to reset the
     * PrintStream in an appropriate manner
     * @return <code>false</code>
     * @see java.io.FilterInputStream#in
     * @see java.io.InputStream#mark(int)
     * @see java.io.InputStream#reset()
     */
    public boolean markSupported() {
        return false;
    }
}

