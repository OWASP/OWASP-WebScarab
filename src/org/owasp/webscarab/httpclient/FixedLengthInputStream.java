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
 * FixedLengthInputStream.java
 *
 * Created on May 12, 2003, 11:10 PM
 */

package org.owasp.webscarab.httpclient;

import java.io.IOException;
import java.io.InputStream;

import java.io.FilterInputStream;

public class FixedLengthInputStream extends FilterInputStream {
    private int max;
    private int read = 0;
    private int mark = 0;
    private boolean closed = false;
    
    public FixedLengthInputStream(InputStream is, int max) {
        super(is);
        this.max=max;
    }
    
    public int available() throws IOException {
        if (closed) {
            throw new IOException("available called on closed stream");
        }
        int canread = max - read;
        int available = super.available();
        if (canread > available) {
            available = canread;
        }
        return available;
    }
    
    public void close() {
        closed = true;
    }
    
    public void mark(int readlimit) {
        super.mark(readlimit);
    }
    
    public boolean markSupported() {
        return super.markSupported();
    }
    
    public int read() throws IOException {
        if (closed) {
            throw new IOException("read called on closed stream");
        }
        int canread = max - read;
        if (canread < 1) {
            canread = 0;
        }
        if (canread>0) {
            int b = super.read();
            if (b > -1) {
                read++;
            }
            return b;
        } else {
            return -1;
        }
    }
    
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }
    
    public int read(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IOException("read called on closed stream");
        }
        int canread = Math.min(len, max - read);
        if (canread>0) {
            int bytesRead = super.read(b,off,canread);
            if (bytesRead > -1) {
                read = read + bytesRead;
            }
            return bytesRead;
        } else {
            return -1;
        }
    }
    
    public long skip(long n) throws IOException {
        if (closed) {
            throw new IOException("skip called on closed stream");
        }
        int canread = max - read;
        if (n > canread) {
            n = canread;
        }
        if (n>0) {
            n = super.skip(n);
            read = read + (int) n;
        }
        return n;
    }
    
    public String toString() {
        return this.getClass().getName() + " on a " + super.in.getClass().getName() + " (" + read + " of " + max + ")";
    }
}
