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
 * DocumentHandler.java
 *
 * Created on April 16, 2004, 5:03 PM
 */

package org.owasp.webscarab.util.swing;

import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.ErrorManager;

import javax.swing.text.Document;
import javax.swing.text.PlainDocument;
import javax.swing.text.BadLocationException;

/**
 *
 * @author  knoppix
 */
public class DocumentHandler extends Handler {
    
    private PlainDocument _doc;
    private int _max = Integer.MAX_VALUE;
    
    /** Creates a new instance of DocumentHandler */
    public DocumentHandler() {
        this(Integer.MAX_VALUE);
    }
    
    public DocumentHandler(int limit) {
        _max = limit;
        _doc = new PlainDocument();
    }
    
    public Document getDocument() {
        return _doc;
    }
    
    public void close() {
    }
    
    public void flush() {
    }
    
    public void publish(LogRecord record) {
        if (!isLoggable(record)) {
            return;
        }
        final String msg;
        try {
            msg = getFormatter().format(record);
        } catch (Exception ex) {
            // We don't want to throw an exception here, but we
            // report the exception to any registered ErrorManager.
            reportError(null, ex, ErrorManager.FORMAT_FAILURE);
            return;
        }
        try {
            makeSpace(msg.length());
            _doc.insertString(_doc.getLength(), msg, null);
            // cr++;
        } catch (Exception ex) {
            // We don't want to throw an exception here, but we
            // report the exception to any registered ErrorManager.
            reportError(null, ex, ErrorManager.WRITE_FAILURE);
        }
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
    
}
