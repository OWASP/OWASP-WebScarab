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
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.swing.event.EventListenerList;

import org.owasp.webscarab.util.MRUCache;
import org.owasp.webscarab.util.ReentrantReaderPreferenceReadWriteLock;

/**
 * Provides a model of the conversations that have been seen
 * @author rogan
 */
public class SiteModel {
    
    private ReentrantReaderPreferenceReadWriteLock _rwl = new ReentrantReaderPreferenceReadWriteLock();
    
    private static final Cookie[] NO_COOKIES = new Cookie[0];
    
    private EventListenerList _listenerList = new EventListenerList();
    
    // keeps a fairly small cache of recently used HttpUrl objects
    private Map _urlCache = new MRUCache(200);
    
    private SiteModelStore _store = null;
    
    private boolean _modified = false;
    
    Logger _logger = Logger.getLogger(getClass().getName());
    
    /**
     * Creates a new ConversationModel backed by the supplied store
     * @param store the store providing long term storage of the conversations
     */
    public SiteModel(SiteModelStore store) {
        if (store == null) throw new NullPointerException("Store may not be null");
        _store = store;
    }
    
    public Sync readLock() {
        return _rwl.readLock();
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
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     * @return the ConversationID that identifies this conversation
     */    
    public ConversationID addConversation(Request request, Response response, String origin) {
        ConversationID id = reserveConversationID();
        addConversation(id, request, response, origin);
        return id;
    }
    
    /**
     * adds a request and a response to the model, also specifying which plugin caused
     * it.
     * @param id the previously reserved ConversationID that identifies this conversation
     * @param request the request
     * @param response the response from the server
     * @param origin the plugin that created this conversation
     */
    public void addConversation(ConversationID id, Request request, Response response, String origin) {
        try {
            // _logger.info("Adding conversation " + id + ": " + request.getURL());
            HttpUrl url = request.getURL();
            addUrl(url); // fires appropriate events
            _rwl.writeLock().acquire();
            _store.setRequest(id, request);
            _store.setResponse(id, response);
            _store.addConversation(id, request.getMethod(), url, response.getStatusLine());
            _store.setConversationProperty(id, "ORIGIN", origin);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            fireConversationAdded(id);
            _rwl.readLock().release();
            addUrlProperty(url, "METHODS", request.getMethod());
            addUrlProperty(url, "STATUS", response.getStatusLine());
            // _logger.info("Added conversation " + id + ": " + request.getURL());
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
    }
    
    /**
     * returns the url of the conversation in question
     * @param conversation the conversation
     * @return the url
     */
    
    public HttpUrl getUrlOf(ConversationID conversation) {
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
            fireConversationChanged(conversation, property);
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
    public void addConversationProperty(ConversationID conversation, String property, String value) {
        try {
            _rwl.writeLock().acquire();
            _store.addConversationProperty(conversation, property, value);
            _rwl.readLock().acquire(); // downgrade to read lock
            _rwl.writeLock().release();
            fireConversationChanged(conversation, property);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
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
        StringBuffer value = new StringBuffer(30);
        value.append(values[0]);
        for (int i=1; i<values.length; i++) value.append(", ").append(values[i]);
        return value.toString();
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
    
    /**
     * the total number of conversations that have been added to the model
     * @return the total number of conversations in the model
     */
    public int getConversationCount() {
        return getConversationCount(null);
    }
    
    /**
     * the number of conversations related to the specified url
     *
     * Note that an url with a query is not considered to be the same as the url without the query, for these purposes
     * @param url the url
     * @return the number of conversations related to the specified URL
     */    
    public int getConversationCount(HttpUrl url) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getConversationCount(url);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * obtains the conversation ID of the conversation at the specified position in the
     * list. Conversations are sorted according to the natural ordering of
     * ConversationID.
     * @return the conversation ID
     * @param index the position in the list
     */
    public ConversationID getConversationAt(int index) {
        return getConversationAt(null, index);
    }
    
    /**
     * obtains the conversation ID of the conversation at the specified position in the
     * list of conversations related to the specified URL. Conversations are sorted
     * according to the natural ordering of ConversationID.
     * @param url the url
     * @param index the index
     * @return the conversation ID
     */    
    public ConversationID getConversationAt(HttpUrl url, int index) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getConversationAt(url, index);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * the position of the supplied conversation id in the list. Conversations are
     * sorted according to the natural ordering on ConversationID
     * @param conversation the conversation ID to look up
     * @return the position in the list
     */
    public int getIndexOfConversation(ConversationID conversation) {
        return getIndexOfConversation(null, conversation);
    }
    
    /**
     * the position of the supplied conversation id in the list of conversations
     * related to the specified URL. Conversations are sorted according to the natural
     * ordering of ConversationID
     * @param url the url
     * @param conversation the conversation ID to look up
     * @return the position in the list
     */    
    public int getIndexOfConversation(HttpUrl url, ConversationID conversation) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getIndexOfConversation(url, conversation);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
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
                                fireUrlAdded(path[i]); // fire with read lock held, so listeners can update themselves
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
            fireUrlChanged(url, property);
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
    public void addUrlProperty(HttpUrl url, String property, String value) {
        addUrl(url);
        try {
            _rwl.writeLock().acquire();
            _store.addUrlProperty(url, property, value);
            _rwl.readLock().acquire();
            _rwl.writeLock().release();
            fireUrlChanged(url, property);
            _rwl.readLock().release();
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
        }
        _modified = true;
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
     * returns the number of urls that logically fall directly "under" the provided
     * URL. That is, the number of direct descendants in the tree. This EXCLUDES queries
     * @param parent the url
     * @return the number of children
     */    
    public int getChildUrlCount(HttpUrl parent) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getChildUrlCount(parent);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * returns the child URL at the position specified
     * @param parent the parent url
     * @param index the position
     * @return the child at the position specified
     */    
    public HttpUrl getChildUrlAt(HttpUrl parent, int index) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getChildUrlAt(parent,index);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
    }
    
    /**
     * returns the number of urls that logically fall directly "under" the provided
     * URL. That is, the number of direct descendants in the tree. This EXCLUDES queries
     * @param parent the url
     * @return the number of children
     */    
    public int getQueryCount(HttpUrl parent) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getUrlQueryCount(parent);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return 0;
        }
    }
    
    /**
     * returns the child URL at the position specified
     * @param parent the parent url
     * @param index the position
     * @return the child at the position specified
     */    
    public HttpUrl getQueryAt(HttpUrl parent, int index) {
        try {
            _rwl.readLock().acquire();
            try {
                return _store.getUrlQueryAt(parent,index);
            } finally {
                _rwl.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted! " + ie);
            return null;
        }
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
    public void addSiteModelListener(SiteModelListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(SiteModelListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeSiteModelListener(SiteModelListener listener) {
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationAdded(id);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a conversation has been removed, after the fact
     * @param id the conversation ID
     * @param position the position in the overall conversation list prior to removal
     * @param urlposition the position in the per-url conversation list prior to removal
     */
    protected void fireConversationRemoved(ConversationID id, int position, int urlposition) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationRemoved(id, position, urlposition);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).conversationChanged(id, property);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlAdded(url);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * tells listeners that a Url has been removed, after the fact
     * @param url the url that was added
     * @param position the index of this url under its parent prior to the removal
     */
    protected void fireUrlRemoved(HttpUrl url, int position) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlRemoved(url, position);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).urlChanged(url, property);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
    /**
     * returns the number of uniquely named cookies that have been added to the model.
     * This does not consider changes in value of cookies.
     * @return the number of cookies
     */
    public int getCookieCount() {
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).cookieAdded(cookie);
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
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==SiteModelListener.class) {
                try {
                    ((SiteModelListener)listeners[i+1]).cookieRemoved(cookie);
                } catch (Exception e) {
                    _logger.severe("Unhandled exception: " + e);
                }
            }
        }
    }
    
}
