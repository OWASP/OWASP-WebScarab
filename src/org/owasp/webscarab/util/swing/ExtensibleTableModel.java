/*
 * ExtensibleTableModel.java
 *
 * Created on September 24, 2004, 8:10 AM
 */

package org.owasp.webscarab.util.swing;

import javax.swing.table.AbstractTableModel;

import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author  knoppix
 */
public abstract class ExtensibleTableModel extends AbstractTableModel {
    
    private List _columns = new ArrayList();
    private ColumnDataListener _columnListener;
    
    /** Creates a new instance of ExtensibleTableModel */
    public ExtensibleTableModel() {
        _columnListener = new ColumnDataListener() {
            public void dataChanged(ColumnDataEvent cde) {
                Object column = cde.getSource();
                int col = _columns.indexOf(column);
                if (col < 0) return;
                Object key = cde.getKey();
                if (key == null) {
                    fireTableStructureChanged();
                } else {
                    int row = indexOfKey(key);
                    if (row > -1) {
                        fireTableCellUpdated(row, col);
                    }
                }
            }
        };
    }
    
    public abstract int getRowCount();
    
    public abstract Object getKeyAt(int row);
    
    public abstract int indexOfKey(Object key);
    
    public void addColumn(ColumnDataModel column) {
        _columns.add(column);
        column.addColumnDataListener(_columnListener);
        fireTableStructureChanged();
    }
    
    public void removeColumn(ColumnDataModel column) {
        int index = _columns.indexOf(column);
        if (index < 0) return;
        column.removeColumnDataListener(_columnListener);
        _columns.remove(index);
        fireTableStructureChanged();
    }
    
    public int getColumnCount() {
        return _columns.size();
    }
    
    /**
     * Returns the name of the column at <code>columnIndex</code>.  This is used
     * to initialize the table's column header name.  Note: this name does
     * not need to be unique; two columns in a table can have the same name.
     *
     * @param	column	the index of the column
     * @return  the name of the column
     */
    public String getColumnName(int column) {
        return ((ColumnDataModel) _columns.get(column)).getColumnName();
    }
    
    /**
     * Returns the most specific superclass for all the cell values
     * in the column.  This is used by the <code>JTable</code> to set up a
     * default renderer and editor for the column.
     *
     * @param column  the index of the column
     * @return the common ancestor class of the object values in the model.
     */
    public Class getColumnClass(int column) {
        return ((ColumnDataModel) _columns.get(column)).getColumnClass();
    }
    
    protected Object getValueAt(Object key, int column) {
        return ((ColumnDataModel) _columns.get(column)).getValue(key);
    }
    
    public Object getValueAt(int row, int column) {
        Object key = getKeyAt(row);
        return getValueAt(key, column);
    }
    
}
