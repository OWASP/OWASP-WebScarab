/*
 * ConversationTableModel.java
 *
 * Created on 19 November 2003, 09:23
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.table.TableModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.event.TableModelEvent;

import javax.swing.ListModel;
import javax.swing.DefaultListModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

import org.owasp.webscarab.model.Conversation;
import java.util.Observer;
import java.util.Observable;

/**
 *
 * @author  rdawes
 */
public class ConversationTableModel extends AbstractTableModel {
    
    /** Creates a new instance of ConversationTableModel */
    
    protected String [] columnNames = {
        "ID", "Method", "Url", "Query",
        "Cookie", "Body", "Status",
        "Set-Cookie", "Checksum", "Size",
        "Origin", "Comment"
    };
    
    private int[] preferredColumnWidths = {
        40, 60, 300, 200,
        200, 100, 80,
        150, 80, 50,
        100, 100
    };
    
    private ListModel _lm;
    private TableModel _me;
    private ConversationListener _cl;
    
    public ConversationTableModel(ListModel listModel) {
        if (listModel == null) {
            throw new NullPointerException("listModel may not be null");
        }
        _lm = listModel;
        _me = this;
        _lm.addListDataListener(new ListModelListener());
        _cl = new ConversationListener();
        for (int i=0; i<_lm.getSize(); i++) {
            Object o = _lm.getElementAt(i);
            if (o instanceof Observable) {
                ((Observable)o).addObserver(_cl);
            }
        }
    }
    
    public String getColumnName(int column) {
        if (column < columnNames.length) {
            return columnNames[column];
        }
        return "";
    }
    
    public int getPreferredColumnWidth(int column) {
        return preferredColumnWidths[column];
    }
    
    public int getColumnCount() {
        return columnNames.length;
    }
    
    public int getRowCount() {
        return _lm.getSize();
    }
    
    public Object getValueAt(int row, int column) {
        if (row<0 || row >= _lm.getSize()) {
            System.err.println("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            return null;
        }
        Conversation c = (Conversation) _lm.getElementAt(row);
        if (column <= columnNames.length) {
            return c.getProperty(columnNames[column].toUpperCase());
        } else {
            System.err.println("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            return null;
        }
    }
    
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnNames[columnIndex].equalsIgnoreCase("Comment");
    }
    
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (rowIndex <0 || rowIndex >= _lm.getSize()) {
            System.err.println("Attempt to get row " + rowIndex + ", column " + columnIndex + " : row does not exist!");
            return;
        }
        if (columnNames[columnIndex].equalsIgnoreCase("Comment")) {
            Conversation c = (Conversation) _lm.getElementAt(rowIndex);
            c.setProperty(columnNames[columnIndex].toUpperCase(), aValue.toString());
            if (_lm instanceof DefaultListModel) {
                ((DefaultListModel)_lm).setElementAt(c, rowIndex); // causes an event to be fired
            } // else we are OK for one table, but any shared tables will not update
        }
    }
    
    private class ListModelListener implements ListDataListener {
        
        /**
         * Sent when the contents of the list has changed in a way
         * that's too complex to characterize with the previous
         * methods. For example, this is sent when an item has been
         * replaced. Index0 and index1 bracket the change.
         *
         * @param e  a <code>ListDataEvent</code> encapsulating the
         *    event information
         *
         */
        public void contentsChanged(ListDataEvent e) {
            for (int i=e.getIndex0(); i<=e.getIndex1(); i++) {
                Object o = _lm.getElementAt(i);
                if (o instanceof Observable) {
                    ((Observable)o).addObserver(_cl);
                }
            }
            fireTableChanged(new TableModelEvent(_me));
        }
        
        /**
         * Sent after the indices in the index0,index1
         * interval have been inserted in the data model.
         * The new interval includes both index0 and index1.
         *
         * @param e  a <code>ListDataEvent</code> encapsulating the
         *    event information
         *
         */
        public void intervalAdded(ListDataEvent e) {
            for (int i=e.getIndex0(); i<=e.getIndex1(); i++) {
                Object o = _lm.getElementAt(i);
                if (o instanceof Observable) {
                    ((Observable)o).addObserver(_cl);
                }
            }
            fireTableChanged(new TableModelEvent(_me, e.getIndex0(), e.getIndex1(),
                TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT));
        }
        
        /** Sent after the indices in the index0,index1 interval
         * have been removed from the data model.  The interval
         * includes both index0 and index1.
         *
         * @param e  a <code>ListDataEvent</code> encapsulating the
         *    event information
         *
         */
        public void intervalRemoved(ListDataEvent e) {
            // we don't remove observers here because we can't get the Conversations from
            // the list. If they are removed, they will not be changing, anyway.
            fireTableChanged(new TableModelEvent(_me, e.getIndex0(), e.getIndex1(),
                TableModelEvent.ALL_COLUMNS, TableModelEvent.DELETE));
        }
        
    }
    
    private class ConversationListener implements Observer {
    
        public void update(Observable o, Object arg) {
            String key = (String) arg;
            for (int i=0; i<_lm.getSize();i++) {
                Object element = _lm.getElementAt(i);
                if (o.equals(element)) {
                    fireTableRowsUpdated(i,i);
                    break;
                }
            }
        }
        
    }
    
}
