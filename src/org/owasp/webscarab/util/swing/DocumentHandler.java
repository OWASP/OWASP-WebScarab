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
