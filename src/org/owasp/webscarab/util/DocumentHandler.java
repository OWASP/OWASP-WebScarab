/*
 * DocumentHandler.java
 *
 * Created on April 16, 2004, 5:03 PM
 */

package org.owasp.webscarab.util;

import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.ErrorManager;

import javax.swing.text.Document;
import javax.swing.text.BadLocationException;

/**
 *
 * @author  knoppix
 */
public class DocumentHandler extends Handler {
    
    private Document _doc;
    private int _allowed = 1000;
    
    /** Creates a new instance of DocumentHandler */
    public DocumentHandler(Document doc) {
        doc.getClass(); // throw null pointer exception if null
        _doc = doc;
    }
    
    public void close() throws SecurityException {
    }
    
    public void flush() {
    }
    
    public void publish(LogRecord record) {
        if (!isLoggable(record)) {
            return;
        }
        String msg;
        try {
            msg = getFormatter().format(record);
        } catch (Exception ex) {
            // We don't want to throw an exception here, but we
            // report the exception to any registered ErrorManager.
            reportError(null, ex, ErrorManager.FORMAT_FAILURE);
            return;
        }
        int cr = 0;
        int pos = -1;
        while ((pos = msg.indexOf("\n", pos+1)) > -1) cr++;
        String text;
        while (_allowed < cr) {
            System.err.println("too many lines, removing a few: " + _allowed + " < " + cr);
            try {
                text = _doc.getText(0, Math.min(_doc.getLength(), 200));
                pos = text.indexOf("\n");
                if (pos > -1) {
                    _doc.remove(0, pos);
                    _allowed++;
                } else {
                    break;
                }
            } catch (BadLocationException ble) {
                System.err.println("BadLocationException removing text from the log: " + ble);
                break;
            }
        }
        try {
            _doc.insertString(_doc.getLength(), msg, null);
        } catch (Exception ex) {
            // We don't want to throw an exception here, but we
            // report the exception to any registered ErrorManager.
            reportError(null, ex, ErrorManager.WRITE_FAILURE);
        }
    }
    
}
