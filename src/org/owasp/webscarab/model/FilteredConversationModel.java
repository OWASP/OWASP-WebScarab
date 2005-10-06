/*
 * FilteredConversationModel.java
 *
 * Created on 13 April 2005, 06:33
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public abstract class FilteredConversationModel extends AbstractConversationModel {
    
    private ConversationModel _model;
    
    // contains conversations that should be visible
    private List _conversations = new ArrayList();
    
    private Logger _logger = Logger.getLogger(getClass().toString());
    
    /** Creates a new instance of FilteredConversationModel */
    public FilteredConversationModel(FrameworkModel model, ConversationModel cmodel) {
        super(model);
        _model = cmodel;
        _model.addConversationListener(new Listener());
        updateConversations();
    }
    
    protected void updateConversations() {
        _conversations.clear();
        try {
            _model.readLock().acquire();
            int count = _model.getConversationCount();
            for (int i=0 ; i<count; i++) {
                ConversationID id = _model.getConversationAt(i);
                if (!shouldFilter(id)) {
                    _conversations.add(id);
                }
            }
        } catch (InterruptedException ie) {
            //            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
    }
    
    public abstract boolean shouldFilter(ConversationID id);
    
    protected boolean isFiltered(ConversationID id) {
        try {
            _model.readLock().acquire();
            return _conversations.indexOf(id) == -1;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return false;
        } finally {
            _model.readLock().release();
        }
    }
    
    public ConversationID getConversationAt(int index) {
        try {
            _model.readLock().acquire();
            return (ConversationID) _conversations.get(index);
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return null;
        } finally {
            _model.readLock().release();
        }
    }
    
    public int getConversationCount() {
        try {
            _model.readLock().acquire();
            return _conversations.size();
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return 0;
        } finally {
            _model.readLock().release();
        }
    }
    
    public int getIndexOfConversation(ConversationID id) {
        try {
            _model.readLock().acquire();
            return Collections.binarySearch(_conversations, id);
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return -1;
        } finally {
            _model.readLock().release();
        }
    }
    
    public Sync readLock() {
        return _model.readLock();
    }
    
    private class Listener implements ConversationListener {
        
        public void conversationAdded(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            if (! shouldFilter(id)) {
                int index = getIndexOfConversation(id);
                if (index < 0) {
                    index = -index - 1;
                    _conversations.add(index, id);
                    fireConversationAdded(id, index);
                }
            }
        }
        
        public void conversationChanged(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (shouldFilter(id)) {
                if (index > -1) {
                    _conversations.remove(index);
                    fireConversationRemoved(id, index);
                }
            } else {
                if (index < 0) {
                    index = -index -1;
                    _conversations.add(index, id);
                    fireConversationAdded(id, index);
                }
            }
        }
        
        public void conversationRemoved(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (index > 0) {
                _conversations.remove(index);
                fireConversationRemoved(id, index);
            }
        }
        
        public void conversationsChanged() {
            updateConversations();
            fireConversationsChanged();
        }
        
    }
    
}
