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
