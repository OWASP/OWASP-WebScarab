/*
 * IDTableModel.java
 *
 * Created on 16 November 2003, 11:08
 */

package org.owasp.webscarab.ui.swing.sessionid;

import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

import javax.swing.ListModel;
import javax.swing.table.AbstractTableModel;

import org.owasp.webscarab.plugin.sessionid.SessionID;

/**
 *
 * @author  rdawes
 */
public class IDTableModel extends AbstractTableModel implements ListDataListener {
    
    ListModel _lm;
    private String[] _columnNames = new String[] { "Number", "Date", "Value", "Integer" };
    
    /** Creates a new instance of IDTableModel */
    public IDTableModel(ListModel lm) {
        _lm = lm;
        if (lm != null) {
            lm.addListDataListener(this);
        }
    }
    
    public String getColumnName(int column) {
        return _columnNames[column];
    }
    
    /** Returns the number of columns in the model. A
     * <code>JTable</code> uses this method to determine how many columns it
     * should create and display by default.
     *
     * @return the number of columns in the model
     * @see #getRowCount
     *
     */
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    /** Returns the number of rows in the model. A
     * <code>JTable</code> uses this method to determine how many rows it
     * should display.  This method should be quick, as it
     * is called frequently during rendering.
     *
     * @return the number of rows in the model
     * @see #getColumnCount
     *
     */
    public int getRowCount() {
        return _lm == null ? 0 : _lm.getSize();
    }
    
    /** Returns the value for the cell at <code>columnIndex</code> and
     * <code>rowIndex</code>.
     *
     * @param	rowIndex	the row whose value is to be queried
     * @param	columnIndex 	the column whose value is to be queried
     * @return	the value Object at the specified cell
     *
     */
    public Object getValueAt(int rowIndex, int columnIndex) {
        SessionID id = (SessionID) _lm.getElementAt(rowIndex);
        switch (columnIndex) {
            case 0 : return new Integer(rowIndex);
            case 1 : return id.getDate();
            case 2 : return id.getValue();
            case 3 : return id.getIntValue();
        }
        return null;
    }
    
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
