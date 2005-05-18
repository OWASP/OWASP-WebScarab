/*
 * ConversationListTableModel.java
 *
 * Created on 04 April 2005, 09:41
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.ConversationListener;
import org.owasp.webscarab.model.ConversationEvent;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import javax.swing.table.AbstractTableModel;

/**
 *
 * @author  rogan
 */
public class ConversationListTableModel extends AbstractTableModel implements ConversationListener {
    
    private ConversationModel _conversationModel;
    
    private final static String[] _columnNames = new String[] { "ID", "Method", "Host", "Path", "Parameters", "Status" };
    
    /** Creates a new instance of ConversationListTableModel */
    public ConversationListTableModel(ConversationModel conversationModel) {
        _conversationModel = conversationModel;
        _conversationModel.addConversationListener(this);
    }
    
    public String getColumnName(int index) {
        return _columnNames[index];
    }
    
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    public int getRowCount() {
        return _conversationModel.getConversationCount(null);
    }
    
    public Object getKeyAt(int rowIndex) {
        return _conversationModel.getConversationAt(null, rowIndex);
    }
    
    public Object getValueAt(int rowIndex, int columnIndex) {
        ConversationID id = (ConversationID) getKeyAt(rowIndex);
        HttpUrl url = _conversationModel.getRequestUrl(id);
        switch (columnIndex) {
            case 0: return id;
            case 1: return _conversationModel.getRequestMethod(id);
            case 2: return url.getScheme() + "://" + url.getHost() + ":" + url.getPort();
            case 3: return url.getPath();
            case 4: return url.getParameters();
            case 5: return _conversationModel.getResponseStatus(id);
        }
        return null;
    }
    
    public void conversationAdded(ConversationEvent evt) {
        fireTableRowsInserted(evt.getPosition(), evt.getPosition());
    }
    
    public void conversationChanged(ConversationEvent evt) {
        fireTableRowsUpdated(evt.getPosition(), evt.getPosition());
    }
    
    public void conversationRemoved(ConversationEvent evt) {
        fireTableRowsDeleted(evt.getPosition(), evt.getPosition());
    }
    
    public void conversationsChanged() {
        fireTableDataChanged();
    }
    
}