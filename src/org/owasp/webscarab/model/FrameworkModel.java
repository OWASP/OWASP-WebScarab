/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * SiteModel.java
 *
 * Created on July 13, 2004, 3:58 PM
 */

package org.owasp.webscarab.model;

import EDU.oswego.cs.dl.util.concurrent.ReadWriteLock;
import EDU.oswego.cs.dl.util.concurrent.Sync;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.logging.Level;

import javax.swing.event.EventListenerList;

import org.owasp.webscarab.util.MRUCache;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

import java.io.File;

/**
 * Provides a model of the conversations that have been seen
 * @author rogan
 */
public class FrameworkModel {
    
    private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    private static final Cookie[] NO_COOKIES = new Cookie[0];
    
    private EventListenerList _listenerList = new EventListenerList();
    
    // keeps a fairly small cache of recently used HttpUrl objects
    private Map _urlCache = new MRUCache(200);
    
    private SiteModelStore _store = null;
    
    private FrameworkUrlModel _urlModel;
    private FrameworkConversationModel _conversationModel;
    
    private boolean _modified = false;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /**
     * Creates a new ConversationModel
     */
    public FrameworkModel() {
        _logger.setLevel(Level.INFO);
        _conversationModel = new FrameworkConversationModel(this);
        _urlModel = new FrameworkUrlModel();
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
        try {
            _rwl.writeLock().acquire();
            if (type.equals("FileSystem") && store instanceof File) {
                try {
                    _store = new FileSystemStore((File) store);
                } catch (Exception e) {
                    throw new StoreException("Error initialising session : " + e.getMessage());
                }
            } else {
                _rwl.writeLock().release();
                throw new StoreException("Unknown store type " + type + " and store " + store);
            }
            _rwl.readLock().acquire(); // downgrade
            _rwl.writeLock().release();
            _urlModel.fireUrlsChanged();
            _conversationModel.fireConversationsChanged();
            fireCookiesChanged();
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        
    }
    
    public Sync readLock() {
        return _rwl.readLock();
    }
    
    public UrlModel getUrlModel() {
        return _urlModel;
    }
    
    public ConversationModel getConversationModel() {
        return _conversationModel;
    }
    
    /**
     * instructs the SiteModel to flush any unwritten data in the underlying store to
     * disk, prior to exit.
     * @throws StoreException if there is any problem writing to the store
     */
    public void flush() throws StoreException {
        if (_modified) {
            try {
                _rwl.readLock().acquire();
                try {
                    _store.flush();
                    _modified = false;
                } finally {
                    _rwl.readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
            }
        }
    }
    
    /**
     * indicates whether there have been modifications to the site model
     *@return true if the model has been modified since it was last flushed, false otherwise
     */
    public boolean isModified() {
        return _modified;
    }
    
    /**
     * reserve a conversation ID for later use. This is mostly used by the Proxy plugin
     * to allow it to add conversations in the order that they are seen, not in the
     * order that they are completed.
     * @return a new ConversationID
     */
    public ConversationID reserveConversationID() {
        return new ConversationID();
    }
    
    /**
     * adds a request and a response to the model, also specifying which plugin caused
     * it.
     * @param id the previously reserved ConversationID that identifies this conversation
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     */
    public void addConversation(ConversationID id, Date when, Request request, Response response, String origin) {
        try {
            HttpUrl url = request.getURL();
            addUrl(url); // fires appropriate events
            _rwl.writeLock().acquire();
            int index = _store.addConversation(id, when, request, response);
            _store.setConversationProperty(id, "ORIGIN", origin);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            _conversationModel.fireConversationAdded(id, index); // FIXME
            _rwl.readLock().release();
            addUrlProperty(url, "METHODS", request.getMethod());
            addUrlProperty(url, "STATUS", response.getStatusLine());
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
    }
    
    public String getConversationOrigin(ConversationID id) {
        return getConversationProperty(id, "ORIGIN");
    }
    
    public Date getConversationDate(ConversationID id) {
        try {
            _rwl.readLock().acquire();
            try {
                String when = getConversationProperty(id, "WHEN");
                if (when == null) return null;
                try {
                    long time = Long.parseLong(when);
                    return new Date(time);
                } catch (NumberFormatException nfe) {
                    System.err.println("NumberFormatException parsing date for Conversation " + id + ": " + nfe);
                    return null;
                }
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns the url of the conversation in question
     * @param conversation the conversation
     * @return the url
     */
    
    public HttpUrl getRequestUrl(ConversationID conversation) {
        try {
            _rwl.readLock().acquire();
            try {
                // this allows us to reuse HttpUrl objects
                if (_urlCache.containsKey(conversation))
                    return (HttpUrl) _urlCache.get(conversation);
                
                String url = getConversationProperty(conversation, "URL");
                try {
                    HttpUrl httpUrl = new HttpUrl(url);
                    _urlCache.put(conversation, httpUrl);
                    return httpUrl;
                } catch (MalformedURLException mue) {
                    System.err.println("Malformed URL for Conversation " + conversation + ": " + mue);
                    return null;
                }
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * sets the specified property of the conversation
     * @param conversation the conversation ID
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setConversationProperty(ConversationID conversation, String property, String value) {
        try {
            _rwl.writeLock().acquire();
            _store.setConversationProperty(conversation, property, value);
            _rwl.readLock().acquire(); // downgrade
            _rwl.writeLock().release();
            _conversationModel.fireConversationChanged(conversation, 0); // FIXME
            fireConversationPropertyChanged(conversation, property);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
    }
    
    /**
     * adds the value to a list of existing values for the specified property and conversation
     * @param conversation the conversation
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addConversationProperty(ConversationID conversation, String property, String value) {
        boolean change = false;
        try {
            _rwl.writeLock().acquire();
            change = _store.addConversationProperty(conversation, property, value);
            _rwl.readLock().acquire(); // downgrade to read lock
            _rwl.writeLock().release();
            if (change) {
                _conversationModel.fireConversationChanged(conversation, 0); // FIXME
                fireConversationPropertyChanged(conversation, property);
            }
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = _modified || change;
        return change;
    }
    
    /**
     * returns a String containing the value that has been identified for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getConversationProperty(ConversationID conversation, String property) {
        String[] values = getConversationProperties(conversation, property);
        if (values == null || values.length == 0) return null;
        if (values.length == 1) return values[0];
        StringBuffer value = new StringBuffer(values[0]);
        for (int i=1; i<values.length; i++) value.append(", ").append(values[i]);
        return value.toString();
    }
    
    public String getRequestMethod(ConversationID id) {
        return getConversationProperty(id, "METHOD");
    }
    
    public String getResponseStatus(ConversationID id) {
        return getConversationProperty(id, "STATUS");
    }
    
    /**
     * returns a String array containing the values that has been set for a particular conversation property
     * @param conversation the conversation id
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getConversationProperties(ConversationID conversation, String property) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getConversationProperties(conversation, property);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    private void addUrl(HttpUrl url) {
        try {
            _rwl.readLock().acquire();
            try {
                if (!_store.isKnownUrl(url)) {
                    HttpUrl[] path = url.getUrlHierarchy();
                    for (int i=0; i<path.length; i++) {
                        if (!_store.isKnownUrl(path[i])) {
                            _rwl.readLock().release(); // must give it up before writing
                            // XXX We could be vulnerable to a race condition here
                            // we should check again to make sure that it does not exist
                            // AFTER we get our writelock
                            
                            // FIXME There is something very strange going on here
                            // sometimes we deadlock if we just do a straight acquire
                            // but there does not seem to be anything competing for the lock.
                            // This works, but it feels like a kluge! FIXME!!!
                            // _rwl.writeLock().acquire();
                            while (!_rwl.writeLock().attempt(5000)) {
                                _logger.severe("Timed out waiting for write lock, trying again");
                                _rwl.debug();
                            }
                            if (!_store.isKnownUrl(path[i])) {
                                _store.addUrl(path[i]);
                                _rwl.readLock().acquire(); // downgrade without giving up lock
                                _rwl.writeLock().release();
                                _urlModel.fireUrlAdded(path[i], 0); // FIXME
                                _modified = true;
                            } else { // modified by some other thread?! Go through the motions . . .
                                _rwl.readLock().acquire();
                                _rwl.writeLock().release();
                            }
                        }
                    }
                }
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    }
    
    /**
     * sets the specified property of the url
     * @param url the url
     * @param property the name of the property to change
     * @param value the value to use
     */
    public void setUrlProperty(HttpUrl url, String property, String value) {
        addUrl(url);
        try {
            _rwl.writeLock().acquire();
            _store.setUrlProperty(url, property, value);
            _rwl.readLock().acquire(); // downgrade write to read
            _rwl.writeLock().release();
            _urlModel.fireUrlChanged(url, 0); // FIXME
            fireUrlPropertyChanged(url, property);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
    }
    
    /**
     * adds the value to a list of existing values for the specified property and Url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addUrlProperty(HttpUrl url, String property, String value) {
        boolean change = false;
        addUrl(url);
        try {
            _rwl.writeLock().acquire();
            change = _store.addUrlProperty(url, property, value);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            if (change) {
                _urlModel.fireUrlChanged(url, 0);
                fireUrlPropertyChanged(url, property);
            }
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = _modified || change;
        return change;
    }
    
    /**
     * returns a String array containing the values that has been set for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return an array of strings representing the property values, possibly zero length
     */
    public String[] getUrlProperties(HttpUrl url, String property) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getUrlProperties(url, property);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns a String containing the value that has been identified for a particular url property
     * @param url the url
     * @param property the name of the property
     * @return the property value, or null if none has been set
     */
    public String getUrlProperty(HttpUrl url, String property) {
        String[] values = getUrlProperties(url, property);
        if (values == null || values.length == 0) return null;
        if (values.length == 1) return values[0];
        StringBuffer value = new StringBuffer(30);
        value.append(values[0]);
        for(int i=1; i< values.length; i++) value.append(", ").append(values[i]);
        return value.toString();
    }
    
    /**
     * returns the request corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the request
     */
    public Request getRequest(ConversationID conversation) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getRequest(conversation);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns the response corresponding to the conversation ID
     * @param conversation the conversation ID
     * @return the response
     */
    public Response getResponse(ConversationID conversation) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getResponse(conversation);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addModelListener(FrameworkListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(FrameworkListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeModelListener(FrameworkListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(FrameworkListener.class, listener);
        }
    }
    
    /**
     * returns the number of uniquely named cookies that have been added to the model.
     * This does not consider changes in value of cookies.
     * @return the number of cookies
     */
    public int getCookieCount() {
        if (_store == null) return 0;
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getCookieCount();
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * returns the number of unique values that have been observed for the specified cookie
     * @param key a key identifying the cookie
     * @return the number of values in the model
     */
    public int getCookieCount(String key) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getCookieCount(key);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * returns a key representing the cookie name at the position specified
     * @return a key which can be used to get values for this cookie
     * @param index which cookie in the list
     */
    public String getCookieAt(int index) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getCookieAt(index);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns the actual Cookie corresponding to the key and position specified
     * @param key the cookie identifier
     * @param index the position in the list
     * @return the cookie
     */
    public Cookie getCookieAt(String key, int index) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getCookieAt(key, index);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(Cookie cookie) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getIndexOfCookie(cookie);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * returns the position of the cookie in its list.
     * (The key is extracted from the cookie itself)
     * @param cookie the cookie
     * @return the position in the list
     */
    public int getIndexOfCookie(String key, Cookie cookie) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getIndexOfCookie(key, cookie);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    public Cookie getCurrentCookie(String key) {
        try {
            _rwl.readLock().acquire();
            try {
                int count = _store.getCookieCount(key);
                return _store.getCookieAt(key, count-1);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * adds a cookie to the model
     * @param cookie the cookie to add
     */
    public void addCookie(Cookie cookie) {
        try {
            _rwl.writeLock().acquire();
            boolean added = _store.addCookie(cookie);
            if (! added) { // we already had the cookie
                _rwl.writeLock().release();
            } else {
                _modified = true;
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireCookieAdded(cookie);
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    }
    
    /**
     * removes a cookie from the model
     * @param cookie the cookie to remove
     */
    public void removeCookie(Cookie cookie) {
        try {
            _rwl.writeLock().acquire();
            boolean deleted = _store.removeCookie(cookie);
            if (deleted) {
                _modified = true;
                _rwl.readLock().acquire();
                _rwl.writeLock().release();
                fireCookieRemoved(cookie);
                _rwl.readLock().release();
            } else {
                _rwl.writeLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
    }
    
    /**
     * returns an array of cookies that would be applicable to a request sent to the url.
     * @param url the url
     * @return an array of cookies, or a zero length array if there are none applicable.
     */
    public Cookie[] getCookiesForUrl(HttpUrl url) {
        try {
            _rwl.readLock().acquire();
            try {
                List cookies = new ArrayList();
                
                String host = url.getHost();
                String path = url.getPath();
                
                int size = getCookieCount();
                for (int i=0; i<size; i++) {
                    String key = getCookieAt(i);
                    Cookie cookie = getCurrentCookie(key);
                    String domain = cookie.getDomain();
                    if (host.equals(domain) || (domain.startsWith(".") && host.endsWith(domain))) {
                        if (path.startsWith(cookie.getPath())) {
                            cookies.add(cookie);
                        }
                    }
                }
                return (Cookie[]) cookies.toArray(NO_COOKIES);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return NO_COOKIES;
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
        FrameworkEvent evt = new FrameworkEvent(this, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookieAdded(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
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
        FrameworkEvent evt = new FrameworkEvent(this, cookie);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookieRemoved(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that all cookies in the model have changed
     */
    protected void fireCookiesChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).cookiesChanged();
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that a conversation property changed
     * @param cookie the cookie
     */
    protected void fireConversationPropertyChanged(ConversationID id, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, id, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).conversationPropertyChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * notifies listeners that an URL property changed
     * @param cookie the cookie
     */
    protected void fireUrlPropertyChanged(HttpUrl url, String property) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        FrameworkEvent evt = new FrameworkEvent(this, url, property);
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==FrameworkListener.class) {
                try {
                    ((FrameworkListener)listeners[i+1]).urlPropertyChanged(evt);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    private class FrameworkUrlModel extends AbstractUrlModel {
        
        public Sync readLock() {
            return _rwl.readLock();
        }
        
        public int getChildCount(HttpUrl parent) {
            if (_store == null) return 0;
            try {
                readLock().acquire();
                try {
                    return _store.getChildCount(parent);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return 0;
            }
        }
        
        public int getIndexOf(HttpUrl url) {
            try {
                readLock().acquire();
                try {
                    return _store.getIndexOf(url);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return -1;
            }
        }
        
        public HttpUrl getChildAt(HttpUrl parent, int index) {
            try {
                readLock().acquire();
                try {
                    return _store.getChildAt(parent, index);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return null;
            }
        }
        
    }
    
    private class FrameworkConversationModel extends AbstractConversationModel {
        
        public FrameworkConversationModel(FrameworkModel model) {
            super(model);
        }
        
        public Sync readLock() {
            return _rwl.readLock();
        }
        
        public ConversationID getConversationAt(int index) {
            try {
                readLock().acquire();
                try {
                    return _store.getConversationAt(null, index);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return null;
            }
        }
        
        public int getConversationCount() {
            if (_store == null) return 0;
            try {
                readLock().acquire();
                try {
                    return _store.getConversationCount(null);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return 0;
            }
        }
        
        public int getIndexOfConversation(ConversationID id) {
            try {
                readLock().acquire();
                try {
                    return _store.getIndexOfConversation(null, id);
                } finally {
                    readLock().release();
                }
            } catch (InterruptedException ie) {
                _logger.severe("Interrupted! " + ie);
                return 0;
            }
        }
        
    }
    
}
