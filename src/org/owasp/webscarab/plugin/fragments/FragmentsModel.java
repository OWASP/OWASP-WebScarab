/*
 * FragmentsModel.java
 *
 * Created on 04 April 2005, 10:30
 */

package org.owasp.webscarab.plugin.fragments;

import EDU.oswego.cs.dl.util.concurrent.Sync;
import EDU.oswego.cs.dl.util.concurrent.ReadWriteLock;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.AbstractConversationModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.plugin.AbstractPluginModel;

import org.owasp.webscarab.util.Encoding;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class FragmentsModel extends AbstractPluginModel {
    
    private FragmentsStore _store = null;
    private FrameworkModel _model = null;
    private FragmentConversationModel _fcm = null;
    
    private ReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of FragmentsModel */
    public FragmentsModel(FrameworkModel model) {
        super(model);
        _model = model;
        _fcm = new FragmentConversationModel();
    }
    
    public void addFragment(HttpUrl url, ConversationID id, String type, String fragment) {
        try {
            _rwl.writeLock().acquire();
            String key = Encoding.hashMD5(fragment);
            int position = _store.putFragment(type, key, fragment);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            _model.addConversationProperty(id, type, key);
            _model.addUrlProperty(url, type, key);
            fireFragmentAdded(url, id, type, key);
            if (position>-1)
                fireFragmentAdded(type, key, position);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    }
    
    public void addRequestCookie(ConversationID id, String cookie) {
        _model.addConversationProperty(id, "COOKIE", cookie);
        // FIXME: fireCookieAdded here
    }
    
    public void addResponseCookie(ConversationID id, HttpUrl url, Cookie cookie) {
        _model.addConversationProperty(id, "SET-COOKIE", cookie.getName() + "=" + cookie.getValue());
        _model.addUrlProperty(url, "SET-COOKIE", cookie.getName());
        // FIXME: fireSetCookieAdded here
    }
    
    public String getRequestCookies(ConversationID id) {
        return _model.getConversationProperty(id, "COOKIE");
    }
    
    public String getResponseCookies(ConversationID id) {
        return _model.getConversationProperty(id, "SET-COOKIE");
    }
    
    public String getResponseCookies(HttpUrl url) {
        return _model.getUrlProperty(url, "SET-COOKIE");
    }
    
    public String[] getUrlFragmentKeys(HttpUrl url, String type) {
        if (type.equals("SCRIPTS") || type.equals("COMMENTS")) {
            return _model.getUrlProperties(url, type);
        } else {
            return new String[0];
        }
    }
    
    public String[] getConversationFragmentKeys(ConversationID id, String type) {
        if (type.equals("SCRIPTS") || type.equals("COMMENTS")) {
            return _model.getConversationProperties(id, type);
        } else {
            return new String[0];
        }
    }
    
    public int getFragmentTypeCount() {
        if (_store == null) return 0;
        return _store.getFragmentTypeCount();
    }
    
    public String getFragmentType(int index) {
        return _store.getFragmentType(index);
    }
    
    public int getFragmentCount(String type) {
        return _store.getFragmentCount(type);
    }
    
    public String getFragmentKeyAt(String type, int position) {
        return _store.getFragmentKeyAt(type, position);
    }
    
    public int indexOfFragment(String type, String key) {
        return _store.indexOfFragment(type, key);
    }
    
    public String getFragment(String key) {
        return _store.getFragment(key);
    }
    
    public void addModelListener(FragmentListener listener) {
        super.addModelListener(listener);
        _listenerList.add(FragmentListener.class, listener);
    }
    
    public void removeModelListener(FragmentListener listener) {
        super.removeModelListener(listener);
        _listenerList.remove(FragmentListener.class, listener);
    }
    
    public ConversationModel getConversationModel() {
        return _fcm;
    }
    
    public void setSelectedFragment(String type, String key) {
        try {
            _rwl.writeLock().acquire();
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _fcm.setSelectedFragment(type, key);
    }
    
    public void setStore(FragmentsStore store) {
        _store = store;
        fireFragmentsChanged();
    }
    
    public void flush() throws StoreException {
        if (_store != null && isModified()) {
            _store.flush();
            setModified(false);
        }
    }
    
    private void fireFragmentsChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FragmentListener.class) {
                try {
                    ((FragmentListener)listeners[i+1]).fragmentsChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    private void fireFragmentAdded(String type, String key, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FragmentListener.class) {
                try {
                    ((FragmentListener)listeners[i+1]).fragmentAdded(type, key, position);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    private void fireFragmentAdded(HttpUrl url, ConversationID id, String type, String key) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FragmentListener.class) {
                try {
                    ((FragmentListener)listeners[i+1]).fragmentAdded(url, id, type, key);
                } catch (Exception e) {
                    _logger.severe("Unhandled : " + e);
                }
            }
        }
    }
    
    private class FragmentConversationModel extends AbstractConversationModel implements FragmentListener {
        
        private String _type = null;
        private String _key = null;
        private List _conversationList = new ArrayList();
        
        public void setSelectedFragment(String type, String key) {
            try {
                _rwl.writeLock().acquire();
                _type = type;
                _key = key;
                _conversationList.clear();
                if (_type != null && _key != null) {
                    ConversationModel cmodel = _model.getConversationModel();
                    int count = cmodel.getConversationCount(null);
                    for (int i=0; i<count; i++) {
                        ConversationID id = cmodel.getConversationAt(null, i);
                        String[] fragments = getConversationFragmentKeys(id,  _type);
                        if (fragments != null) {
                            for (int j=0; j<fragments.length; j++) {
                                if (fragments[j].equals(_key)) {
                                    _conversationList.add(id);
                                    break;
                                }
                            }
                        }
                    }
                }
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireConversationsChanged();
                _rwl.readLock().release();
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
        
        public ConversationID getConversationAt(HttpUrl url, int index) {
            if (url != null)
                _logger.warning("Request for a conversation with a non-null url! NOT IMPLEMENTED!");
            return (ConversationID) _conversationList.get(index);
        }
        
        public int getConversationCount(HttpUrl url) {
            if (url != null)
                _logger.warning("Request for a conversation with a non-null url! NOT IMPLEMENTED!");
            return _conversationList.size();
        }
        
        public int getIndexOfConversation(HttpUrl url, ConversationID id) {
            if (url != null)
                _logger.warning("Request for a conversation with a non-null url! NOT IMPLEMENTED!");
            return Collections.binarySearch(_conversationList, id);
        }
        
        public Sync readLock() {
            return _rwl.readLock();
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
        
        public void fragmentAdded(String type, String key, int position) {}
        
        public void fragmentAdded(HttpUrl url, ConversationID id, String type, String key) {
            if (_type != null && _key != null) {
                if (_type.equals(type) && _key.equals(key)) {
                    int index = getIndexOfConversation(null, id);
                    if (index < 0) {
                        try {
                            _rwl.writeLock().acquire();
                            _conversationList.add(-index-1, id);
                            _rwl.readLock().acquire();
                            _rwl.writeLock().release();
                            fireConversationAdded(id,  -index-1);
                            _rwl.readLock().release();
                        } catch (InterruptedException ie) {
                            _logger.severe("Interrupted! " + ie);
                        }
                    }
                }
            }
        }
        
        public void fragmentsChanged() {
            try {
                _rwl.writeLock().acquire();
                _key = null;
                _type = null;
                _conversationList.clear();
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireConversationsChanged();
                _rwl.readLock().release();
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
        
        public void pluginRunStatusChanged(boolean running, boolean stopping) {}
        
        public void pluginStatusChanged(String status) {}
        
    }
}
