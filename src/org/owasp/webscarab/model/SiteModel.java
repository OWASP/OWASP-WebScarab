package org.owasp.webscarab.model;

import org.owasp.util.URLUtil;

import java.util.ArrayList;

import java.util.TreeMap;
import java.util.Map;
import java.util.Collections;
import java.util.Iterator;

import java.net.URL;
import java.net.MalformedURLException;

import javax.swing.ListModel;
import javax.swing.DefaultListModel;

import javax.swing.tree.TreePath;
import javax.swing.tree.TreeModel;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;

import org.owasp.util.Convert;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

// SiteModel.java

/** SiteModel represents the most significant part of the WebScarab system. It contains the
 * conversations, as well as the information about all the URLs that have been
 * seen.
 */
public class SiteModel {
    
    private DefaultListModel _conversationList;  // maintains a list of conversations
    private Map _urlinfo;              // maps urls to attrs
    
    private SiteModelStore _store = null;
    
    private URLTreeModel _urltree;
    
    private CookieJar _cookieJar;
    
    /**
     *  Constructor
     */
    public SiteModel() {
        _conversationList = new DefaultListModel();
        _urlinfo = Collections.synchronizedMap(new TreeMap());
        _urltree = new URLTreeModel();
        _cookieJar = new CookieJar();
    } // constructor SiteModel
    
    // returns the conversation ID
    public String addConversation(Conversation conversation, Request request, Response response) {
        String id;
        synchronized (_conversationList) {
            if (_conversationList.getSize()>0) {
                id = ((Conversation)_conversationList.getElementAt(_conversationList.getSize()-1)).getProperty("ID");
                id = Integer.toString(Integer.valueOf(id).intValue()+1);
            } else {
                id = "1";
            }
            conversation.setProperty("ID", id);
            _conversationList.addElement(conversation);
        }
        if (_store != null) {
            try {
                _store.writeRequest(id, request);
                _store.writeResponse(id, response);
            } catch (StoreException se) {
                System.err.println("Error writing conversation " + id + " to the store : " + se);
            }
        }
        return id;
    }
    
    public Conversation getConversation(String id) {
        Conversation c = null;
        String cid = null;
        // FIXME !! There must be a better way to search for the conversation than this!
        // Fortunately, it is not called often
        synchronized (_conversationList) {
            for (int i=0; i<_conversationList.size(); i++) {
                c = (Conversation) _conversationList.getElementAt(i);
                if (c != null) {
                    cid = c.getProperty("ID");
                    if (cid != null && cid.equals(id)) {
                        return c;
                    }
                }
            }
        }
        return null;
    }
    
    public String addFragment(String fragment) {
        String key = hashMD5(fragment.getBytes());
        if (_store != null) {
            try {
                _store.writeFragment(key, fragment);
                return key;
            } catch (StoreException se) {
                System.err.println("Error writing fragment to the store : " + se);
            }
        }
        return null;
    }
    
    public String getFragment(String key) {
        if (_store != null) {
            try {
                return _store.readFragment(key);
            } catch (StoreException se) {
                System.err.println("Error reading fragment from the store : " + se);
            }
        }
        return null;
    }
    
    public Request getRequest(String id) {
        if (_store != null) {
            try {
                return _store.readRequest(id);
            } catch (StoreException se) {
                System.err.println("Error reading Request " + id + " from the store : " + se);
                return null;
            }
        } else {
            return null;
        }
    }
    
    public Response getResponse(String id) {
        if (_store != null) {
            try {
                return _store.readResponse(id);
            } catch (StoreException se) {
                System.err.println("Error reading Response " + id + " from the store : " + se);
                return null;
            }
        } else {
            return null;
        }
    }
    
    public URLInfo getURLInfo(URL url) {
        return getURLInfo(URLUtil.schemeAuthPath(url));
    }

    private URLInfo getURLInfo(String url) {
        URLInfo ui;
        boolean newUrl = false;
        synchronized (_urlinfo) {
            ui = (URLInfo) _urlinfo.get(url);
            if (ui == null) {
                newUrl = true;
                ui = new URLInfo(url);
                _urlinfo.put(url, ui);
            }
        }
        if (newUrl) {
            try {
                _urltree.add(url);
            } catch (Exception e) {
                System.err.println("Error adding " + url + " to the tree");
            }
        }
        return ui;
    }
    
    
    public void setSessionStore(Object store) throws StoreException {
        if (store != null && store instanceof SiteModelStore) {
            _store = (SiteModelStore) store;
            synchronized(_cookieJar) {
                _cookieJar.clear();
                _cookieJar.addCookies(_store.readCookies());
            }
            synchronized (_conversationList) {
                _conversationList.clear();
                Conversation[] conversation = _store.readConversations();
                for (int i=0; i<conversation.length; i++) {
                    _conversationList.addElement(conversation[i]);
                }
            }
            synchronized (_urlinfo) {
                _urltree.clear();
                _urlinfo.clear();
                URLInfo[] urlinfo = _store.readURLInfo();
                for (int i=0; i<urlinfo.length; i++) {
                    _urlinfo.put(urlinfo[i].getURL(), urlinfo[i]);
                    _urltree.add(urlinfo[i].getURL());
                }
                // Fixme : if we keep a tree of URLInfo's, we should fire a tree changed
                // event here
            }
        } else {
            throw new StoreException("object passed does not implement SiteModelStore!");
        }
    }
    
    public void saveSessionData() throws StoreException {
        if (_store != null) {
            synchronized (_conversationList) {
                Conversation[] conversations = new Conversation[_conversationList.size()];
                for (int i=0; i<conversations.length; i++) {
                    conversations[i] = (Conversation) _conversationList.get(i);
                }
                _store.writeConversations(conversations);
            }
            synchronized (_urlinfo) {
                URLInfo[] urlinfo = new URLInfo[_urlinfo.size()];
                Iterator urls = _urlinfo.keySet().iterator();
                for (int i=0; i<urlinfo.length; i++) {
                    urlinfo[i] = (URLInfo) _urlinfo.get(urls.next());
                }
                _store.writeURLInfo(urlinfo);
            }
            synchronized (_cookieJar) {
                _store.writeCookies(_cookieJar.getAllCookies());
            }
        }
    }
    
    public DefaultListModel getConversationListModel() {
        return _conversationList;
    }
    
    public TreeModel getURLTreeModel() {
        return _urltree;
    }
    
    public CookieJar getCookieJar() {
        return _cookieJar;
    }
    

    // FIXME - this should be in a shared place
    private String hashMD5 (byte[] bytes) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance( "MD5" );
            md.update( bytes );
        }
        catch ( NoSuchAlgorithmException e ) {
            e.printStackTrace();
            // it's got to be there
        }
        return Convert.toHexString( md.digest() );
    }
}
