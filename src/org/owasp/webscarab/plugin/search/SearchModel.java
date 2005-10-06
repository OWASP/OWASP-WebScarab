/*
 * SearchModel.java
 *
 * Created on 19 June 2005, 01:41
 */

package org.owasp.webscarab.plugin.search;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import org.owasp.webscarab.model.*;
import org.owasp.webscarab.plugin.*;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

import java.util.Map;
import java.util.TreeMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class SearchModel extends AbstractPluginModel {
    
    public final static String PROPERTY_FILTER = "Filter";
    public final static String PROPERTY_SEARCHES = "Searches";
    
    private FrameworkModel _model;
    private SearchConversationModel _conversationModel;
    private UrlModel _urlModel;
    
    private Map _searches = new TreeMap();
    
    private String _description = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of SearchModel */
    public SearchModel(FrameworkModel model) {
        _model = model;
        _conversationModel = new SearchConversationModel(_model);
    }
    
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    public Sync readLock() {
        return _rwl.readLock();
    }
    
    public void addSearch(String description, String expression) {
        _logger.info("Adding search " + description);
        _searches.put(description, expression);
        _changeSupport.firePropertyChange(PROPERTY_SEARCHES, null, null);
    }
    
    public String[] getSearches() {
        return (String[]) _searches.keySet().toArray(new String[_searches.size()]);
    }
    
    public String getSearchExpression(String description) {
        return (String) _searches.get(description);
    }
    
    public void removeSearch(String description) {
        _searches.remove(description);
        _changeSupport.firePropertyChange(PROPERTY_SEARCHES, null, null);
    }
    
    public void setFilter(String description) {
        if (_description == null && description == null) {
            // do nothing
        } else if (_description == null || description == null) {
            changeFilter(description);
        } else if (!_description.equals(description)) {
            changeFilter(description);
        } else {
            // do nothing
        }
    }
    
    private void changeFilter(String description) {
        try {
            _rwl.writeLock().acquire();
            Object old = _description;
            _description = description;
            _conversationModel.refilter();
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            _changeSupport.firePropertyChange(PROPERTY_FILTER, old, description);
            _conversationModel.fireConversationsChanged();
            _rwl.readLock().release();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void setSearchMatch(ConversationID id, String description, boolean matches) {
        if (matches) {
            _model.addConversationProperty(id, "SEARCH", description);
        } else {
            String[] searches = _model.getConversationProperties(id, "SEARCH");
            if (searches != null) {
                // FIXME this causes all the SEARCH results to be set to
                // null, with the consequence that conversations are removed
                // and immediately readded as we put the property back
                // Need to implement a 
                // FrameworkModel.removeConversationProperty(id, name, value)
                // method somehow
                _model.setConversationProperty(id, "SEARCH", null);
                for (int i=0; i<searches.length; i++) {
                    if (!searches[i].equals(description)) {
                        _model.addConversationProperty(id, "SEARCH", searches[i]);
                    }
                }
            }
        }
    }
    
    public boolean hasSearchMatch(ConversationID id, String description) {
        if (description == null) return false;
        String[] searches = _model.getConversationProperties(id, "SEARCH");
        if (searches == null) return false;
        for (int i=0; i<searches.length; i++) {
            if (searches[i].equals(description)) return true;
        }
        return false;
    }
    
    private class SearchConversationModel extends AbstractConversationModel {
        
        private List _conversations = new ArrayList();
        
        public SearchConversationModel(FrameworkModel model) {
            super(model);
            model.getConversationModel().addConversationListener(new Listener());
        }
        
        public void refilter() {
            _conversations.clear();
            if (_description != null) {
                ConversationModel cmodel = _model.getConversationModel();
                int count = cmodel.getConversationCount();
                for (int i=0; i< count; i++) {
                    ConversationID id = cmodel.getConversationAt(i);
                    if (hasSearchMatch(id, _description)) {
                        _conversations.add(id);
                    }
                }
            }
        }
        
        public ConversationID getConversationAt(int index) {
            return (ConversationID) _conversations.get(index);
        }
        
        public int getConversationCount() {
            return _conversations.size();
        }
        
        public int getIndexOfConversation(ConversationID id) {
            return _conversations.indexOf(id);
        }
        
        public Sync readLock() {
            return _rwl.readLock();
        }
        
        public void fireConversationsChanged() {
            super.fireConversationsChanged();
        }
        
        private class Listener implements ConversationListener {
            
            public void conversationAdded(ConversationEvent evt) {
            }
            
            public void conversationChanged(ConversationEvent evt) {
                ConversationID id = evt.getConversationID();
                int index = Collections.binarySearch(_conversations, id);
                if (hasSearchMatch(id, _description)) {
                    if (index < 0) {
                        index = -index -1;
                        try {
                            _rwl.writeLock().acquire();
                            _conversations.add(index, id);
                            _rwl.readLock().acquire();
                            _rwl.writeLock().release();
                            SearchConversationModel.this.fireConversationAdded(id, index);
                            _rwl.readLock().release();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                } else {
                    if (index >= 0) {
                        try {
                            _rwl.writeLock().acquire();
                            _conversations.remove(index);
                            _rwl.readLock().acquire();
                            _rwl.writeLock().release();
                            SearchConversationModel.this.fireConversationRemoved(id, index);
                            _rwl.readLock().release();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    
                }
            }
            
            public void conversationRemoved(ConversationEvent evt) {
                ConversationID id = evt.getConversationID();
                int index = Collections.binarySearch(_conversations, id);
                if (index > -1) {
                    try {
                        _rwl.writeLock().acquire();
                        _conversations.remove(index);
                        _rwl.readLock().acquire();
                        _rwl.writeLock().release();
                        SearchConversationModel.this.fireConversationRemoved(id, index);
                        _rwl.readLock().release();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            
            public void conversationsChanged() {
                setFilter(null);
            }
            
        }
        
    }
}
