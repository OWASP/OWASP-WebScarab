/*
 * ByteViewer.java
 *
 * Created on November 4, 2003, 6:09 PM
 */

package org.owasp.webscarab.ui.swing.editors;

/**
 *
 * @author  rdawes
 */
public interface ByteArrayEditor {
    
    String getName();
    
    String[] getContentTypes();
    
    void setEditable(boolean editable);
    
    void setBytes(byte[] bytes);
    
    boolean isModified();
    
    byte[] getBytes();

}
