/*
 * ConversationTableModel.java
 *
 * Created on June 21, 2004, 6:05 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.SiteModelAdapter;

import org.owasp.webscarab.util.swing.ExtensibleTableModel;

import javax.swing.table.AbstractTableModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationTableModel extends ExtensibleTableModel {
    
    protected SiteModel _model = null;
    protected HttpUrl _url = null;
    
    private Listener _listener = new Listener();
    
    protected Logger _logger = Logger.getLogger(getClass().getName());
    
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
    
    public void setUrl(HttpUrl url) {
        _url = url;
        fireTableDataChanged();
    }
    
    public Object getKeyAt(int row) {
        return _model.getConversationAt(_url, row);
    }
    
    public int indexOfKey(Object key) {
        return _model.getIndexOfConversation(_url, (ConversationID) key);
    }
    
    public int getRowCount() {
        if (_model == null) return 0;
        return _model.getConversationCount(_url);
    }
    
    public int getColumnCount() {
        return super.getColumnCount()+1;
    }
    
    public Object getValueAt(int row, int column) {
        Object key = getKeyAt(row);
        if (column == 0) return key;
        return super.getValueAt(key, column-1);
    }
    
    /**
     * Returns the name of the column at <code>column</code>.  This is used
     * to initialize the table's column header name.  Note: this name does
     * not need to be unique; two columns in a table can have the same name.
     *
     * @param	column the index of the column
     * @return  the name of the column
     */
    public String getColumnName(int column) {
        if (column == 0) return "ID";
        return super.getColumnName(column-1);
    }
    
    /**
     * Returns the most specific superclass for all the cell values
     * in the column.  This is used by the <code>JTable</code> to set up a
     * default renderer and editor for the column.
     *
     * @param column the index of the column
     * @return the common ancestor class of the object values in the model.
     */
    public Class getColumnClass(int column) {
        if (column == 0) return ConversationID.class;
        return super.getColumnClass(column-1);
    }
    
    protected void addedConversation(ConversationID id) {
        int row = indexOfKey(id);
        fireTableRowsInserted(row, row);
    }
    
    protected void removedConversation(ConversationID id, int position, int urlposition) {
        fireTableDataChanged();
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
