/*
 * ConversationTableModel.java
 *
 * Created on June 21, 2004, 6:05 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.SiteModelAdapter;

import javax.swing.AbstractListModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationListModel extends AbstractListModel {
    
    private SiteModel _model = null;
    private Listener _listener = new Listener();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationListModel(SiteModel model) {
        setModel(model);
    }
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationListModel() {
    }
    
    public void setModel(SiteModel model) {
        int oldsize = getSize();
        if (_model != null) _model.removeSiteModelListener(_listener);
        if (oldsize>0) {
            _model = null;
            fireIntervalRemoved(this, 0, oldsize);
        }
        _model = model;
        if (_model != null) _model.addSiteModelListener(_listener);
        fireContentsChanged(this, 0, getSize());
    }
    
    public Object getElementAt(int index) {
        return _model.getConversationAt(index);
    }
    
    public int getSize() {
        if (_model == null) return 0; 
        return _model.getConversationCount();
    }
    
    protected void addedConversation(ConversationID id) {
        int row = _model.getIndexOfConversation(id);
        fireIntervalAdded(this, row, row);
    }
    
    protected void changedConversation(ConversationID id, String property) {
        int row = _model.getIndexOfConversation(id);
        fireContentsChanged(this, row, row);
    }
    
    protected void removedConversation(ConversationID id, int position, int urlposition) {
        fireIntervalRemoved(this, position, position);
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
