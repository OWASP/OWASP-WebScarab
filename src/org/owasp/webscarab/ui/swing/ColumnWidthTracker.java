/*
 * ColumnWidthTracker.java
 *
 * Created on 03 June 2005, 10:16
 */

package org.owasp.webscarab.ui.swing;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.HashMap;
import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;

import javax.swing.JTable;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.event.TableColumnModelEvent;
import javax.swing.event.TableColumnModelListener;

import org.owasp.webscarab.model.Preferences;

/**
 *
 * @author  rogan
 */
public class ColumnWidthTracker implements PropertyChangeListener, TableColumnModelListener {
    
    private static HashMap _trackers = new HashMap();
    
    private String _key;
    
    private List _tracked = new LinkedList();
    
    public static ColumnWidthTracker getTracker(String key) {
        ColumnWidthTracker tracker = (ColumnWidthTracker) _trackers.get(key);
        if (tracker == null) {
            tracker = new ColumnWidthTracker(key);
            _trackers.put(key, tracker);
        }
        return tracker;
    }
    
    /** Creates a new instance of ColumnWidthTracker */
    protected ColumnWidthTracker(String key) {
        _key = key;
    }
    
    public void addTable(JTable table) {
        TableColumnModel tcm = table.getColumnModel();
        for (int i=0; i<tcm.getColumnCount(); i++) {
            TableColumn tc = tcm.getColumn(i);
            addColumn(tc);
        }
        tcm.addColumnModelListener(this);
        _tracked.add(tcm);
    }
    
    public void removeTable(JTable table) {
        TableColumnModel tcm = table.getColumnModel();
        for (int i=0; i<tcm.getColumnCount(); i++) {
            TableColumn tc = tcm.getColumn(i);
            tc.removePropertyChangeListener(this);
        }
        tcm.removeColumnModelListener(this);
        _tracked.remove(tcm);
    }
    
    public void propertyChange(PropertyChangeEvent evt) {
        String property = evt.getPropertyName();
        if (property == null || !"preferredWidth".equals(property)) return;
        if (! (evt.getSource() instanceof TableColumn)) return;
        TableColumn tc = (TableColumn) evt.getSource();
        String name = String.valueOf(tc.getHeaderValue());
        int width = tc.getPreferredWidth();
        Preferences.setPreference(_key + "." + name + ".width", String.valueOf(width));
        Iterator it = _tracked.iterator();
        while (it.hasNext()) {
            TableColumnModel tcm = (TableColumnModel) it.next();
            for (int i=0; i<tcm.getColumnCount(); i++) {
                TableColumn tc2 = tcm.getColumn(i);
                String name2 = String.valueOf(tc2.getHeaderValue());
                if (name.equals(name2) && tc != tc2 && tc2.getPreferredWidth() != width)
                    tc2.setPreferredWidth(width);
            }
        }
    }
    
    private void addColumn(TableColumn tc) {
        String name = String.valueOf(tc.getHeaderValue());
        String preferredWidth = Preferences.getPreference(_key + "." + name + ".width");
        if (preferredWidth != null) {
            try {
                int width = Integer.parseInt(preferredWidth);
                tc.setPreferredWidth(width);
            } catch (NumberFormatException nfe) {}
        }
        tc.addPropertyChangeListener(this);
    }
    
    public void columnAdded(TableColumnModelEvent e) {
        int index = e.getToIndex();
        TableColumnModel tcm = (TableColumnModel) e.getSource();
        TableColumn tc = tcm.getColumn(index);
        addColumn(tc);
    }
    
    public void columnMarginChanged(javax.swing.event.ChangeEvent e) {}
    
    public void columnMoved(TableColumnModelEvent e) {}
    
    public void columnRemoved(TableColumnModelEvent e) {
        int index = e.getToIndex();
        TableColumnModel tcm = (TableColumnModel) e.getSource();
        if (index >= tcm.getColumnCount()) return;
        TableColumn tc = tcm.getColumn(index);
        tc.removePropertyChangeListener(this);
    }
    
    public void columnSelectionChanged(javax.swing.event.ListSelectionEvent e) {}
    
}
