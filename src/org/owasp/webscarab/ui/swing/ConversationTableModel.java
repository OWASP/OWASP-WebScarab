/*
 * ConversationTableModel.java
 *
 * Created on June 21, 2004, 6:05 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.SiteModelAdapter;

import javax.swing.table.AbstractTableModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationTableModel extends AbstractTableModel {
    
    private String[] _columnNames = new String[] {
        "ID", "Method", "Url", "Parameters",
        "Status", "Origin"
    };
    
    protected SiteModel _model = null;
    
    private Listener _listener = new Listener();
    
    protected Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationTableModel() {
    }
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationTableModel(SiteModel model) {
        setModel(model);
    }
    
    public void setModel(SiteModel model) {
        if (_model != null) {
            _model.removeSiteModelListener(_listener);
        }
        _model = model;
        if (_model != null) {
            _model.addSiteModelListener(_listener);
        }
        fireTableDataChanged();
    }
    
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    public int getRowCount() {
        if (_model == null) return 0;
        return _model.getConversationCount();
    }
    
    public Object getValueAt(int row, int column) {
        ConversationID id = _model.getConversationAt(row);
        return getValueAt(id, column);
    }
    
    protected Object getValueAt(ConversationID id, int column) {
        String property = _columnNames[column].toUpperCase();
        switch (column) {
            case 0: return id;
            // case 1: method is just a property
            case 2: return _model.getUrlOf(id).getSHPP();
            case 3: return _model.getUrlOf(id).getParameters();
            default: return _model.getConversationProperty(id, property);
        }
    }
    
    /**
     * Returns the name of the column at <code>columnIndex</code>.  This is used
     * to initialize the table's column header name.  Note: this name does
     * not need to be unique; two columns in a table can have the same name.
     *
     * @param	columnIndex	the index of the column
     * @return  the name of the column
     */
    public String getColumnName(int columnIndex) {
        return _columnNames[columnIndex];
    }
    
    /**
     * Returns the most specific superclass for all the cell values
     * in the column.  This is used by the <code>JTable</code> to set up a
     * default renderer and editor for the column.
     *
     * @param columnIndex  the index of the column
     * @return the common ancestor class of the object values in the model.
     */
    public Class getColumnClass(int columnIndex) {
        if (columnIndex == 0) return ConversationID.class;
        return super.getColumnClass(columnIndex);
    }
    
    protected void addedConversation(ConversationID id) {
        int row = _model.getIndexOfConversation(id);
        fireTableRowsInserted(row, row);
    }
    
    protected void changedConversation(ConversationID id, String property) {
        int row = _model.getIndexOfConversation(id);
        fireTableRowsUpdated(row, row);
    }
    
    protected void removedConversation(ConversationID id, int position, int urlposition) {
        fireTableRowsDeleted(position,  position);
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(final ConversationID id) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        addedConversation(id);
                    }
                });
            } catch (Exception e) {
                _logger.warning("Exception! " + e);
            }
        }
        
        public void conversationChanged(final ConversationID id, final String property) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        changedConversation(id, property);
                    }
                });
            } catch (Exception e) {
                _logger.warning("Exception! " + e);
            }
        }
        
        public void conversationRemoved(final ConversationID id, final int position, final int urlposition) {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        removedConversation(id, position, urlposition);
                    }
                });
            } catch (Exception e) {
                _logger.warning("Exception! " + e);
            }
        }
        
    }
    
}
