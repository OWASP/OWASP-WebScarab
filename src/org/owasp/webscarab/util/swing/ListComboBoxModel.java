/*
 * ListComboBoxModel.java
 *
 * Created on October 1, 2003, 11:15 PM
 */

package org.owasp.webscarab.util.swing;

import javax.swing.AbstractListModel;
import javax.swing.ListModel;
import javax.swing.ComboBoxModel;

import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */
public class ListComboBoxModel extends AbstractListModel implements ComboBoxModel {
    
    ListModel _list;
    Object _selected = null;
    
    Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of ListComboBoxModel */
    public ListComboBoxModel(ListModel list) {
        _list = list;
        _list.addListDataListener(new MyListener());
    }
    
    public Object getElementAt(int index) {
        return _list.getElementAt(index);
    }
    
    public Object getSelectedItem() {
        return _selected;
    }
    
    public int getSize() {
        return _list.getSize();
    }
    
    public void setSelectedItem(Object anItem) {
        _selected = anItem;
    }
    
    private class MyListener implements ListDataListener {
        
        public void contentsChanged(ListDataEvent e) {
            fireContentsChanged(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
        public void intervalAdded(ListDataEvent e) {
            fireIntervalAdded(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
        public void intervalRemoved(ListDataEvent e) {
            fireIntervalRemoved(ListComboBoxModel.this, e.getIndex0(), e.getIndex1());
        }
        
    }
}
