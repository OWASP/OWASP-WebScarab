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
    
    /** Creates a new instance of DocumentOutputStream */
    public DocumentOutputStream() {
    }
    
    public Document getDocument() {
        return _doc;
    }
    
    public void write(int b) throws IOException {
        try {
            _doc.insertString(_doc.getLength(), new String(new byte[] {(byte)(b&0xFF)}, "ISO-8859-1"), null);
        } catch (BadLocationException ble) {
            throw new IOException(ble.getMessage());
        }
    }
    
    public void write(byte[] buff) throws IOException {
        try {
            _doc.insertString(_doc.getLength(), new String(buff, "ISO-8859-1"), null);
        } catch (BadLocationException ble) {
            throw new IOException(ble.getMessage());
        }
    }
    
}
