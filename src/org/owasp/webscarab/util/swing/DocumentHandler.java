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

import javax.swing.SwingUtilities;
import javax.swing.text.Document;
import javax.swing.text.PlainDocument;

/**
 *
 * @author  knoppix
 */
public class DocumentHandler extends Handler {
    
    private PlainDocument _doc;
    private int _allowed = 100;
    
    /** Creates a new instance of DocumentHandler */
    public DocumentHandler() {
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
        Runnable publish = new Runnable() {
            public void run() {
                try {
                    _doc.insertString(_doc.getLength(), msg, null);
                    // cr++;
                } catch (Exception ex) {
                    // We don't want to throw an exception here, but we
                    // report the exception to any registered ErrorManager.
                    reportError(null, ex, ErrorManager.WRITE_FAILURE);
                }
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            publish.run();
        } else {
            SwingUtilities.invokeLater(publish);
        }
    }
    
}
