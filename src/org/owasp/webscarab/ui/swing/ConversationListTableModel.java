/*
 * ConversationListTableModel.java
 *
 * Created on 04 April 2005, 09:41
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import javax.swing.ListModel;
import javax.swing.table.AbstractTableModel;

import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;

/**
 *
 * @author  rogan
 */
public class ConversationListTableModel extends AbstractTableModel implements ListDataListener {
    
    private SiteModel _siteModel;
    private ListModel _listModel;
    
    private final static String[] _columnNames = new String[] { "ID", "Method", "Host", "Path", "Parameters", "Status" };
    
    /** Creates a new instance of ConversationListTableModel */
    public ConversationListTableModel(SiteModel siteModel, ListModel listModel) {
        _siteModel = siteModel;
        _listModel = listModel;
        _listModel.addListDataListener(this);
    }
    
    public String getColumnName(int index) {
        return _columnNames[index];
    }
    
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    public int getRowCount() {
        return _listModel.getSize();
    }
    
    public Object getKeyAt(int rowIndex) {
        return _listModel.getElementAt(rowIndex);
    }
    
    public Object getValueAt(int rowIndex, int columnIndex) {
        ConversationID id = (ConversationID) getKeyAt(rowIndex);
        HttpUrl url = _siteModel.getUrlOf(id);
        switch (columnIndex) {
            case 0: return id;
            case 1: return _siteModel.getConversationProperty(id, "METHOD");
            case 2: return url.getScheme() + "://" + url.getHost() + ":" + url.getPort();
            case 3: return url.getPath();
            case 4: return url.getParameters();
            case 5: return _siteModel.getConversationProperty(id, "STATUS");
        }
        return null;
    }
    
    public void contentsChanged(ListDataEvent e) {
        fireTableRowsUpdated(e.getIndex0(), e.getIndex1());
    }
    
    public void intervalAdded(ListDataEvent e) {
        fireTableRowsInserted(e.getIndex0(), e.getIndex1());
    }
    
    public void intervalRemoved(ListDataEvent e) {
        fireTableRowsDeleted(e.getIndex0(), e.getIndex1());
    }
    
}
