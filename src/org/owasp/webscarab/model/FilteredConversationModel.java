/*
 * FilteredConversationModel.java
 *
 * Created on 13 April 2005, 06:33
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import java.util.ArrayList;

import org.owasp.webscarab.util.MRUCache;

/**
 *
 * @author  rogan
 */
public abstract class FilteredConversationModel extends AbstractConversationModel {
    
    private ConversationModel _model;
    
    private MRUCache _filtered = new MRUCache(16);
    
    /** Creates a new instance of FilteredConversationModel */
    public FilteredConversationModel(FrameworkModel model, ConversationModel cmodel) {
        super(model);
        _model = cmodel;
        _model.addConversationListener(new Listener());
        updateFiltered(null);
    }
    
    protected ArrayList updateFiltered(HttpUrl url) {
        ArrayList filtered = new ArrayList();
        try {
            _model.readLock().acquire();
            int count = _model.getConversationCount(null);
            for (int i=0 ; i<count; i++) {
                ConversationID id = _model.getConversationAt(null, i);
                if (shouldFilter(id)) {
                    filtered.add(id);
                }
            }
            _filtered.put(url, filtered);
            return filtered;
        } catch (InterruptedException ie) {
            //            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return null;
        } finally {
            _model.readLock().release();
        }
    }
    
    public abstract boolean shouldFilter(ConversationID id);
    
    protected boolean isFiltered(HttpUrl url, ConversationID id) {
        try {
            _model.readLock().acquire();
            ArrayList filtered = (ArrayList) _filtered.get(url);
            if (filtered == null)
                filtered = updateFiltered(url);
            return filtered.indexOf(id) > -1;
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return false;
        } finally {
            _model.readLock().release();
        }
    }
    
    public ConversationID getConversationAt(HttpUrl url, int index) {
        try {
            _model.readLock().acquire();
            ArrayList filtered = (ArrayList) _filtered.get(url);
            if (filtered == null)
                filtered = updateFiltered(url);
            return (ConversationID) filtered.get(index);
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return null;
        } finally {
            _model.readLock().release();
        }
    }
    
    public int getConversationCount(HttpUrl url) {
        try {
            _model.readLock().acquire();
            return _model.getConversationCount(null) - _filtered.size();
        } catch (InterruptedException ie) {
            // _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
            return 0;
        } finally {
            _model.readLock().release();
        }
    }
    
    public int getIndexOfConversation(HttpUrl url, ConversationID id) {
        try {
            _model.readLock().acquire();
            ArrayList filtered = (ArrayList) _filtered.get(url);
            if (filtered == null)
                filtered = updateFiltered(url);
            return filtered.indexOf(id);
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
        }
        
        public void conversationChanged(ConversationEvent evt) {
        }
        
        public void conversationRemoved(ConversationEvent evt) {
        }
        
        public void conversationsChanged() {
        }
        
    }
    
}
