/*
 * ListComboBoxModel.java
 *
 * Created on October 1, 2003, 11:15 PM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.ListModel;
import javax.swing.ComboBoxModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

/**
 *
 * @author  rdawes
 */
public class ListComboBoxModel implements ComboBoxModel {
    
    ListModel _list;
    Object _selected = null;
    
    /** Creates a new instance of ListComboBoxModel */
    public ListComboBoxModel(ListModel list) {
        _list = list;
    }
    
    public void addListDataListener(ListDataListener l) {
        _list.addListDataListener(l);
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
    
    public void removeListDataListener(ListDataListener l) {
        _list.removeListDataListener(l);
    }
    
    public void setSelectedItem(Object anItem) {
        _selected = anItem;
    }
    
}
