/*
 * NotifiableListModel.java
 *
 * Created on 17 November 2003, 04:04
 */

package org.owasp.webscarab.util;

/**
 *
 * @author  rdawes
 */
public class NotifiableListModel extends javax.swing.DefaultListModel {
    
    /** Creates a new instance of NotifiableListModel */
    public NotifiableListModel() {
    }
    
    public void contentsChanged() {
        fireContentsChanged(this, 0, super.getSize());
    }
    
    public void contentsChanged(int index0, int index1) {
        fireContentsChanged(this, index0, index1);
    }
}
