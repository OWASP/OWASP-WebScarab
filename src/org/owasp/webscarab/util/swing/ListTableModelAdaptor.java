/*
 * ListTableModelAdaptor.java
 *
 * Created on 31 March 2004, 09:23
 */

package org.owasp.webscarab.util.swing;

import javax.swing.table.TableModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.event.TableModelEvent;

import javax.swing.ListModel;
import javax.swing.DefaultListModel;
import javax.swing.event.ListDataListener;
import javax.swing.event.ListDataEvent;

/**
 *
 * @author  rdawes
 */
public class ListTableModelAdaptor extends AbstractTableModel {
    
    private ListModel _lm;
    private ListModelListener _lml = new ListModelListener();
    private TableRow _row;
    private boolean _showIndex = false;
    
    public ListTableModelAdaptor() {
        this(null, null, false);
    }
    
    public ListTableModelAdaptor(ListModel listModel, TableRow rowModel) {
        this(listModel, rowModel, false);
    }
    
    public ListTableModelAdaptor(ListModel listModel, TableRow rowModel, boolean index) {
        setListModel(listModel);
        setRowModel(rowModel);
        _showIndex = index;
    }
    
    public void setListModel(ListModel listModel) {
        if (_lm != null) {
            _lm.removeListDataListener(_lml);
        }
        _lm = listModel;
        if (_lm != null) {
            _lm.addListDataListener(_lml);
        }
        fireTableDataChanged();
    }
    
    public void setRowModel(TableRow rowModel) {
        _row = rowModel;
        fireTableStructureChanged();
    }
    
    public int getColumnCount() {
        if (_row != null) {
            return _row.getColumnCount() + (_showIndex ? 1 : 0);
        } else {
            return 0 + (_showIndex ? 1 : 0);
        }
    }
    
    public String getColumnName(int column) {
        if (_showIndex) {
            if (column == 0) {
                return "index";
            } else {
                column = column - 1;
            }
        }
        if (_row != null) {
            return _row.getColumnName(column);
        } else {
            return "";
        }
    }
    
    public Class getColumnClass(int column) {
        if (_showIndex) {
            if (column == 0) {
                return Integer.class;
            } else {
                column = column - 1;
            }
        }
        if (_row != null) {
            return _row.getColumnClass(column);
        } else {
            return Object.class;
        }
    }
    
    public int getRowCount() {
        if (_lm != null) {
            return _lm.getSize();
        } else {
            return 0;
        }
    }
    
    public Object getValueAt(int row, int column) {
        if (_showIndex) {
            if (column == 0) {
                return new Integer(row);
            } else {
                column = column - 1;
            }
        }
        if (_row != null) {
            return _row.getValueAt(_lm.getElementAt(row), column);
        } else {
            return null;
        }
    }
    
    public boolean isCellEditable(int row, int column) {
        if (_showIndex) {
            if (column == 0) {
                return false;
            } else {
                column = column - 1;
            }
        }
        if (_row != null) {
            return _row.isFieldEditable(_lm.getElementAt(row), column);
        } else {
            return false;
        }
    }
    
    public void setValueAt(Object aValue, int row, int column) {
        if (_showIndex) {
            if (column == 0) {
            } else {
                column = column - 1;
            }
        }
        if (_row != null) {
            _row.setValueAt(aValue, _lm.getElementAt(row), column);
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
            fireTableRowsUpdated(e.getIndex0(), e.getIndex1());
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
            fireTableRowsInserted(e.getIndex0(), e.getIndex1());
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
            fireTableRowsDeleted(e.getIndex0(), e.getIndex1());
        }
        
    }
    
}
