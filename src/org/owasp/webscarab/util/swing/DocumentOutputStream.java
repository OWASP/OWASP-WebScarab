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
 * DocumentOutputStream.java
 *
 * Created on August 20, 2004, 6:50 PM
 */

package org.owasp.webscarab.util.swing;

import java.io.OutputStream;
import java.io.IOException;

import javax.swing.text.Document;
import javax.swing.text.PlainDocument;
import javax.swing.text.BadLocationException;

/**
 *
 * @author  knoppix
 */
public class DocumentOutputStream extends OutputStream {
    
    PlainDocument _doc = new PlainDocument();
    private int _max;
    
    /** Creates a new instance of DocumentOutputStream */
    public DocumentOutputStream() {
        this(Integer.MAX_VALUE);
    }
    
    public DocumentOutputStream(int max) {
        _max = max;
    }
    
    public Document getDocument() {
        return _doc;
    }
    
    private void makeSpace(int count) {
        int length = _doc.getLength();
        if (length + count < _max) return;
        try {
            if (count > _max) {
                _doc.remove(0, length);
            } else {
                int min = length + count - _max;
                String remove = _doc.getText(min, Math.min(500, length - min));
                int cr = remove.indexOf("\n");
                if (cr<0) {
                    min = min + remove.length();
                } else {
                    min = Math.min(min + cr + 1, length);
                }
                _doc.remove(0, min);
            }
        } catch (BadLocationException ble) {
            System.err.println("BLE! " + ble);
        }
    }
    
    public void write(int b) throws IOException {
        try {
            makeSpace(1);
            _doc.insertString(_doc.getLength(), new String(new byte[] {(byte)(b&0xFF)}, "ISO-8859-1"), null);
        } catch (BadLocationException ble) {
            throw new IOException(ble.getMessage());
        }
    }
    
    public void write(byte[] buff) throws IOException {
        write(buff,0, buff.length);
    }
    
    public void write(byte[] buff, int off, int length) throws IOException {
        try {
            makeSpace(length);
            _doc.insertString(_doc.getLength(), new String(buff, off, length, "ISO-8859-1"), null);
        } catch (BadLocationException ble) {
            throw new IOException(ble.getMessage());
        }
    }
    
}
