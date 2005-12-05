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
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

/**
 *
 * @author  rogan
 */
public abstract class FilteredConversationModel extends AbstractConversationModel {
    
    private ConversationModel _model;
    
    private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
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
        try {
            _rwl.writeLock().acquire();
            _conversations.clear();
            int count = _model.getConversationCount();
            for (int i=0 ; i<count; i++) {
                ConversationID id = _model.getConversationAt(i);
                if (!shouldFilter(id)) {
                    _conversations.add(id);
                }
            }
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            fireConversationsChanged();
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        }
    }
    
    public abstract boolean shouldFilter(ConversationID id);
    
    protected boolean isFiltered(ConversationID id) {
        try {
            _rwl.readLock().acquire();
            return _conversations.indexOf(id) == -1;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return false;
        } finally {
            _rwl.readLock().release();
        }
    }
    
    public ConversationID getConversationAt(int index) {
        try {
            _rwl.readLock().acquire();
            return (ConversationID) _conversations.get(index);
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return null;
        } finally {
            _rwl.readLock().release();
        }
    }
    
    public int getConversationCount() {
        try {
            _rwl.readLock().acquire();
            return _conversations.size();
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return 0;
        } finally {
            _rwl.readLock().release();
        }
    }
    
    public int getIndexOfConversation(ConversationID id) {
        try {
            _rwl.readLock().acquire();
            return Collections.binarySearch(_conversations, id);
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return -1;
        } finally {
            _rwl.readLock().release();
        }
    }
    
    public Sync readLock() {
        return _rwl.readLock();
    }
    
    private class Listener implements ConversationListener {
        
        public void conversationAdded(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            if (! shouldFilter(id)) {
                try {
                    _rwl.writeLock().acquire();
                    int index = getIndexOfConversation(id);
                    if (index < 0) {
                        index = -index - 1;
                        _conversations.add(index, id);
                    }
                    _rwl.readLock().acquire();
                    _rwl.writeLock().release();
                    fireConversationAdded(id, index);
                    _rwl.readLock().release();
                } catch (InterruptedException ie) {
                    // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                }
            }
        }
        
        public void conversationChanged(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (shouldFilter(id)) {
                if (index > -1) {
                    try {
                        _rwl.writeLock().acquire();
                        _conversations.remove(index);
                        _rwl.readLock().acquire();
                        _rwl.writeLock().release();
                        fireConversationRemoved(id, index);
                        _rwl.readLock().release();
                    } catch (InterruptedException ie) {
                        // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                    }
                }
            } else {
                if (index < 0) {
                    index = -index -1;
                    try {
                        _rwl.writeLock().acquire();
                        _conversations.add(index, id);
                        _rwl.readLock().acquire();
                        _rwl.writeLock().release();
                        fireConversationAdded(id, index);
                        _rwl.readLock().release();
                    } catch (InterruptedException ie) {
                        // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                    }
                }
            }
        }
        
        public void conversationRemoved(ConversationEvent evt) {
            ConversationID id = evt.getConversationID();
            int index = getIndexOfConversation(id);
            if (index > -1) {
                try {
                    _rwl.writeLock().acquire();
                    _conversations.remove(index);
                    _rwl.readLock().acquire();
                    _rwl.writeLock().release();
                    fireConversationRemoved(id, index);
                    _rwl.readLock().release();
                } catch (InterruptedException ie) {
                    // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
                }
            }
        }
        
        public void conversationsChanged() {
            updateConversations();
        }
        
    }
    
}
