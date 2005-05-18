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
    public FilteredConversationModel(ConversationModel model) {
        _model = model;
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
        } catch (InterruptedException ie) {
//            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return filtered;
    }
    
    public abstract boolean shouldFilter(ConversationID id);
    
    protected boolean isFiltered(HttpUrl url, ConversationID id) {
        ArrayList filtered = (ArrayList) _filtered.get(url);
        if (filtered == null)
            filtered = updateFiltered(url);
        return filtered.indexOf(id) > -1;
    }
    
    public ConversationID getConversationAt(HttpUrl url, int index) {
        
        return null;
    }
    
    public int getConversationCount(HttpUrl url) {
        return _model.getConversationCount(null) - _filtered.size();
    }
    
    public int getIndexOfConversation(HttpUrl url, ConversationID id) {
        return -1;
    }
    
    public Sync readLock() {
        return _model.readLock();
    }
    
    public Request getRequest(ConversationID id) {
        return _model.getRequest(id);
    }
    
    public String getRequestMethod(ConversationID id) {
        return _model.getRequestMethod(id);
    }
    
    public HttpUrl getRequestUrl(ConversationID id) {
        return _model.getRequestUrl(id);
    }
    
    public Response getResponse(ConversationID id) {
        return _model.getResponse(id);
    }
    
    public String getResponseStatus(ConversationID id) {
        return _model.getResponseStatus(id);
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
