/*
 * AbstractSiteModel.java
 *
 * Created on 04 March 2005, 10:35
 */

package org.owasp.webscarab.model;

import java.util.Set;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;

import EDU.oswego.cs.dl.util.concurrent.Sync;

import javax.swing.event.EventListenerList;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class FilteredSiteModel implements SiteModel {
    
    protected SiteModel _model;
    private Set _filteredUrls = null;
    private Set _implicitUrls = null;
    private List _filteredConversations = null;
    
    private boolean _filterUrls;
    private boolean _filterConversations;
    private boolean _filterCookies;
    
    protected EventListenerList _listenerList = new EventListenerList();
    
    protected Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of AbstractSiteModel */
    public FilteredSiteModel(SiteModel model, boolean filterUrls, boolean filterConversations) {
        _model = model;
        _filterUrls = filterUrls;
        _filterConversations = filterConversations;
        try {
            _model.readLock().acquire();
            if (_filterUrls) updateFilteredUrls();
            _model.addModelListener(new Listener());
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
    }
    
    public Sync readLock() {
        return _model.readLock();
    }
    
    protected boolean shouldFilter(HttpUrl url) {
        return false;
    }
    
    protected boolean isFiltered(HttpUrl url) {
        return _filteredUrls != null && _filteredUrls.contains(url);
    }
    
    protected void setFiltered(HttpUrl url, boolean filtered) {
        if (_filteredUrls == null) _filteredUrls = new HashSet();
        if (filtered) {
            _filteredUrls.add(url);
        } else {
            _filteredUrls.remove(url);
        }
    }
    
    public boolean isImplicit(HttpUrl url) {
        return _implicitUrls != null && _implicitUrls.contains(url);
    }
    
    protected void setImplicit(HttpUrl url, boolean filtered) {
        if (_implicitUrls == null) _implicitUrls = new HashSet();
        if (filtered) {
            _implicitUrls.add(url);
        } else {
            _implicitUrls.remove(url);
        }
    }
    
    private boolean isVisible(HttpUrl url) {
        return isImplicit(url) || ! isFiltered(url);
    }
    
    public int getIndexOfUrl(HttpUrl url) {
        if (! _filterUrls) return _model.getIndexOfUrl(url);
        try {
            _model.readLock().acquire();
            int index = 0;
            HttpUrl parent = url.getParentUrl();
            int count = _model.getChildUrlCount(parent);
            for (int i = 0; i < count; i++) {
                HttpUrl sibling = _model.getChildUrlAt(parent, i);
                int compare = sibling.compareTo(url);
                if (compare<0 && isVisible(sibling)) {
                    index++;
                } else if (compare == 0) {
                    return index;
                } else return -index -1;
            }
            return -index -1;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return -1;
    }
    
    public HttpUrl getChildUrlAt(HttpUrl url, int index) {
        if (! _filterUrls) return _model.getChildUrlAt(url, index);
        int pos = -1;
        int count = -1;
        try {
            _model.readLock().acquire();
            count = _model.getChildUrlCount(url);
            for (int i = 0; i < count; i++) {
                HttpUrl child = _model.getChildUrlAt(url, i);
                if (isVisible(child)) pos++;
                if (pos == index) return child;
            }
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        throw new ArrayIndexOutOfBoundsException("looking for child " + index + " of " + count + " of " + url);
    }
    
    public int getIndexOfQuery(HttpUrl url) {
        if (! _filterUrls) return _model.getIndexOfQuery(url);
        try {
            _model.readLock().acquire();
            int index = 0;
            HttpUrl parent = url.getParentUrl();
            int count = _model.getQueryCount(parent);
            for (int i = 0; i < count; i++) {
                HttpUrl sibling = _model.getQueryAt(parent, i);
                int compare = sibling.compareTo(url);
                if (compare<0 && isVisible(sibling)) {
                    index++;
                } else if (compare == 0) {
                    return index;
                } else return -index -1;
            }
            return -index -1;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return -1;
    }
    
    public HttpUrl getQueryAt(HttpUrl url, int index) {
        if (! _filterUrls) return _model.getQueryAt(url, index);
        int pos = -1;
        try {
            _model.readLock().acquire();
            int count = _model.getQueryCount(url);
            for (int i = 0; i < count; i++) {
                HttpUrl child = _model.getQueryAt(url, i);
                if (!isFiltered(child)) pos++;
                if (pos == index) return child;
            }
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        throw new ArrayIndexOutOfBoundsException("looking for query " + index + " of " + (pos-1) + " of " + url);
    }
    
    private void updateFilteredUrls() {
        if (_filteredUrls != null) _filteredUrls.clear();
        if (_implicitUrls != null) _implicitUrls.clear();
        recurseTree(null);
    }
    
    public int getChildUrlCount(HttpUrl url) {
        if (! _filterUrls) return _model.getChildUrlCount(url);
        try {
            _model.readLock().acquire();
            int count = _model.getChildUrlCount(url);
            int mycount = 0;
            for (int i=0; i<count; i++) {
                if (isVisible(_model.getChildUrlAt(url, i))) mycount++;
            }
            return mycount;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return -1;
    }
    
    public int getQueryCount(HttpUrl url) {
        if (! _filterUrls) return _model.getQueryCount(url);
        try {
            _model.readLock().acquire();
            int count = _model.getQueryCount(url);
            int mycount = 0;
            for (int i=0; i<count; i++) {
                if (isVisible(_model.getQueryAt(url, i))) mycount++;
            }
            return mycount;
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted waiting for the read lock! " + ie.getMessage());
        } finally {
            _model.readLock().release();
        }
        return -1;
    }
    
    private void recurseTree(HttpUrl parent) {
        int count = _model.getQueryCount(parent);
        for (int i=0; i<count; i++) {
            HttpUrl url = _model.getQueryAt(parent, i);
            if (shouldFilter(url)) {
                setFiltered(url, true);
            } else {
                grow(url);
            }
        }
        count = _model.getChildUrlCount(parent);
        for (int i=0; i<count; i++) {
            HttpUrl url = _model.getChildUrlAt(parent, i);
            if (shouldFilter(url)) {
                setFiltered(url, true);
            } else {
                grow(url);
            }
            recurseTree(url);
        }
    }
    
    /* adds url, and marks any previously filtered intermediate nodes as implicit
     * fires events for all node that becomes visible
     */
    private void grow(HttpUrl url) {
        HttpUrl[] path = url.getUrlHierarchy();
        for (int i=0; i<path.length-1; i++) {
            if (! isVisible(path[i])) {
                setImplicit(path[i], true);
                fireUrlAdded(path[i]);
            }
        }
        fireUrlAdded(url);
    }
    
    /* removes url and any implicit parents. Fires events for the all urls removed
     *
     */
    private void prune(HttpUrl url) {
        fireUrlRemoved(url);
        HttpUrl[] path = url.getUrlHierarchy();
        for (int i=path.length-2; i>=0; i--) {
            if (isImplicit(path[i]) && getChildUrlCount(path[i])==0 && getQueryCount(path[i])==0) {
                setImplicit(path[i], false);
                fireUrlRemoved(path[i]);
            }
        }
    }
    
    public void addConversation(ConversationID id, Request request, Response response, String origin) {
        _model.addConversation(id, request, response, origin);
    }
    
    public ConversationID addConversation(Request request, Response response, String origin) {
        ConversationID id = _model.reserveConversationID();
        addConversation(id, request, response, origin);
        return id;
    }
    
    public int getConversationCount(HttpUrl url) {
        return _model.getConversationCount(url);
    }
    
    public Cookie[] getCookiesForUrl(HttpUrl url) {
        return _model.getCookiesForUrl(url);
    }
    
    public void addCookie(Cookie cookie) {
        _model.addCookie(cookie);
    }
    
    public Request getRequest(ConversationID id) {
        return _model.getRequest(id);
    }
    
    public Response getResponse(ConversationID id) {
        return _model.getResponse(id);
    }
    
    public String getUrlProperty(HttpUrl url, String property) {
        return _model.getUrlProperty(url, property);
    }
    
    public String getConversationProperty(ConversationID id, String property) {
        return _model.getConversationProperty(id, property);
    }
    
    public ConversationID getConversationAt(HttpUrl url, int index) {
        return _model.getConversationAt(url, index);
    }
    
    public int getIndexOfConversation(HttpUrl url, ConversationID id) {
        return _model.getIndexOfConversation(url, id);
    }
    
    public HttpUrl getUrlOf(ConversationID id) {
        return _model.getUrlOf(id);
    }
    
    public boolean addConversationProperty(ConversationID conversation, String property, String value) {
        return _model.addConversationProperty(conversation, property, value);
    }
    
    public boolean addUrlProperty(HttpUrl url, String property, String value) {
        return _model.addUrlProperty(url, property, value);
    }
    
    public ConversationID getConversationAt(int index) {
        return _model.getConversationAt(index);
    }
    
    public int getConversationCount() {
        return _model.getConversationCount();
    }
    
    public String[] getConversationProperties(ConversationID conversation, String property) {
        return _model.getConversationProperties(conversation, property);
    }
    
    public String getCookieAt(int index) {
        return _model.getCookieAt(index);
    }
    
    public Cookie getCookieAt(String key, int index) {
        return _model.getCookieAt(key, index);
    }
    
    public int getCookieCount() {
        return _model.getCookieCount();
    }
    
    public int getCookieCount(String key) {
        return _model.getCookieCount(key);
    }
    
    public Cookie getCurrentCookie(String key) {
        return _model.getCurrentCookie(key);
    }
    
    public int getIndexOfConversation(ConversationID conversation) {
        return _model.getIndexOfConversation(conversation);
    }
    
    public int getIndexOfCookie(Cookie cookie) {
        return _model.getIndexOfCookie(cookie);
    }
    
    public int getIndexOfCookie(String key, Cookie cookie) {
        return _model.getIndexOfCookie(key, cookie);
    }
    
    public String[] getUrlProperties(HttpUrl url, String property) {
        return _model.getUrlProperties(url, property);
    }
    
    public void removeCookie(Cookie cookie) {
        _model.removeCookie(cookie);
    }
    
    public ConversationID reserveConversationID() {
        return _model.reserveConversationID();
    }
    
    public void setConversationProperty(ConversationID conversation, String property, String value) {
        _model.setConversationProperty(conversation, property, value);
    }
    
    public void setUrlProperty(HttpUrl url, String property, String value) {
        _model.setUrlProperty(url, property, value);
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addModelListener(SiteModelListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(SiteModelListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeModelListener(SiteModelListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(SiteModelListener.class, listener);
        }
    }
    
    /**
     * tells listeners that a new Conversation has been added
     * @param id the conversation
     */
    protected void fireConversationAdded(ConversationID id) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.CONVERSATION_ADDED, id, null);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * tells listeners that a conversation has been removed, after the fact
     * @param id the conversation ID that was removed
     */
    protected void fireConversationRemoved(ConversationID id) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.CONVERSATION_REMOVED, id, null);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * fired to tell listeners that a particular conversation has had a property change
     * @param id the conversation
     * @param property the name of the property that was changed
     */
    protected void fireConversationChanged(ConversationID id, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.CONVERSATION_CHANGED, id, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * notifies listeners that a completely new cookie was added
     * @param cookie the cookie
     */    
    protected void fireCookieAdded(Cookie cookie) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.COOKIE_ADDED, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).cookieAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * notifies listeners that all values for cookie have been removed.
     * @param cookie the last cookie that was removed
     */    
    protected void fireCookieRemoved(Cookie cookie) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.COOKIE_REMOVED, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).cookieRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * notifies listeners that all values in the model have changed.
     */    
    protected void fireDataChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.DATA_CHANGED);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).dataChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * tells listeners that a new Url has been added
     * @param url the url that was added
     */
    protected void fireUrlAdded(HttpUrl url) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.URL_ADDED, url, null);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * tells listeners that a Url has been removed, after the fact
     * @param url the url that was removed
     */
    protected void fireUrlRemoved(HttpUrl url) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.URL_REMOVED, url, null);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * fired to tell listeners that a particular Url has had a property change
     * @param url the url that was changed
     * @param property the name of the property that was changed
     */
    protected void fireUrlChanged(HttpUrl url, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        SiteModelEvent evt = new SiteModelEvent(this, SiteModelEvent.URL_CHANGED, url, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                    e.printStackTrace();
                }
            }
        }
    }
    
    private class Listener implements SiteModelListener {
        
        public Listener() {
        }
        
        public void conversationAdded(SiteModelEvent evt) {
            fireConversationAdded(evt.getConversationID());
        }
        
        public void conversationChanged(SiteModelEvent evt) {
            fireConversationChanged(evt.getConversationID(), evt.getPropertyName());
        }
        
        public void conversationRemoved(SiteModelEvent evt) {
            fireConversationRemoved(evt.getConversationID());
        }
        
        public void cookieAdded(SiteModelEvent evt) {
            fireCookieAdded(evt.getCookie());
        }
        
        public void cookieRemoved(SiteModelEvent evt) {
            fireCookieRemoved(evt.getCookie());
        }
        
        public void dataChanged(SiteModelEvent evt) {
            updateFilteredUrls();
            fireDataChanged();
        }
        
        public void urlAdded(SiteModelEvent evt) {
            HttpUrl url = evt.getUrl();
            if (! _filterUrls) {
                fireUrlAdded(url);
            } else {
                if (! shouldFilter(url)) {
                    grow(url);
                } else {
                    setFiltered(url, true);
                }
            }
        }
        
        public void urlChanged(SiteModelEvent evt) {
            HttpUrl url = evt.getUrl();
            String property = evt.getPropertyName();
            if (! _filterUrls) {
                fireUrlChanged(url, property);
            } else {
                if (shouldFilter(url)) { // it is now filtered
                    if (isVisible(url)) { // we could previously see it
                        if (getChildUrlCount(url)>0 || getQueryCount(url)>0) { // it has children
                            setFiltered(url, true);
                            setImplicit(url, true);
                            fireUrlChanged(url, property);
                        } else { // it has no children, hide it and any implicit parents
                            setFiltered(url, true);
                            prune(url);
                        }
                    } // else there is nothing to do to an already invisible node
                } else { // it is now not filtered
                    if (! isVisible(url)) { // it was previously hidden
                        setFiltered(url, false);
                        grow(url);
                    } else {
                        fireUrlChanged(url, property);
                    }
                }
            }
        }
        
        public void urlRemoved(SiteModelEvent evt) {
            HttpUrl url = evt.getUrl();
            if (! _filterUrls) {
                fireUrlAdded(url);
            } else {
                if (isVisible(url)) {
                    prune(url);
                } else {
                    setFiltered(url, false);
                }
            }
        }
        
        public void conversationsChanged(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
        public void cookiesChanged(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
        public void urlsChanged(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
        public void credentialAdded(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
        public void credentialRemoved(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
        public void credentialsChanged(org.owasp.webscarab.model.SiteModelEvent evt) {
        }
        
    }
    
}