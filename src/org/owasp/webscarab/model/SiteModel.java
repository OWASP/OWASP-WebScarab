package org.owasp.webscarab.model;

import org.owasp.util.URLUtil;

import org.owasp.webscarab.plugin.spider.SequencedTreeMap;

import java.util.ArrayList;

import java.util.TreeMap;
import java.util.Map;
import java.util.Collections;
import java.util.Iterator;

import java.net.URL;
import java.net.MalformedURLException;

import javax.swing.DefaultListModel;
import javax.swing.table.TableModel;
import javax.swing.table.AbstractTableModel;

import java.util.logging.Logger;

import javax.swing.tree.TreePath;
import javax.swing.tree.TreeModel;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;

// SiteModel.java

/** SiteModel represents the most significant part of the WebScarab system. It contains the
 * conversations, as well as the information about all the URLs that have been
 * seen.
 */
public class SiteModel {
    
    private SequencedTreeMap _conversationList;  // maintains a list of conversations
    private Map _urlinfo;              // maps urls to attrs
    
    private Logger logger = Logger.getLogger("WebScarab");
    
    private ConversationTableModel _ctm = new ConversationTableModel();
    
    private SiteModelStore _store = null;
    
    private URLTreeModel _urltree;
    
    private CookieJar _cookieJar;
    
    /**
     *  Constructor
     */
    public SiteModel() {
        _conversationList = new SequencedTreeMap();
        _urlinfo = Collections.synchronizedMap(new TreeMap());
        _urltree = new URLTreeModel();
        _cookieJar = new CookieJar();
    } // constructor SiteModel
    
    // returns the conversation ID
    public String addConversation(Conversation conversation, Request request, Response response) {
        String id;
        synchronized (_conversationList) {
            id = Integer.toString(_conversationList.size()+1); // FIXME!! Don't use size here!
            conversation.setProperty("ID", id);
            _conversationList.put(id, conversation);
            int row = _conversationList.size();
            _ctm.fireTableRowsInserted(row, row);
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
    
    /** Given a conversation id, returns the corresponding Conversation
     * @return the requested Conversation, or null if it does not exist
     * @param id the requested "opaque" conversation id
     */
    public Conversation getConversation(String id) {
        synchronized (_conversationList) {
            if (_conversationList.containsKey(id)) {
                return (Conversation) _conversationList.get(id);
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
        synchronized (_urlinfo) {
            ui = (URLInfo) _urlinfo.get(url);
            if (ui == null) {
                try {
                    _urltree.add(url);
                } catch (Exception e) {
                    System.err.println("Error adding " + url + " to the tree");
                }
                ui = new URLInfo(url);
                _urlinfo.put(url, ui);
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
                    _conversationList.put(conversation[i].getProperty("ID"),conversation[i]);
                }
                _ctm.fireTableDataChanged();
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
    
    public TableModel getConversationTableModel() {
        return _ctm;
    }
    
    public TreeModel getURLTreeModel() {
        return _urltree;
    }
    
    public CookieJar getCookieJar() {
        return _cookieJar;
    }
    
    public class ConversationTableModel extends AbstractTableModel {
        
        protected String [] columnNames = {
            "ID", "Method", "Url", "Query",
            "Cookie", "Body", "Status",
            "Set-Cookie", "Checksum", "Size",
            "Origin", "Comment"
        };
        
        private Logger logger = Logger.getLogger("za.org.dragon.exodus.ConversationTableModel");
        
        public ConversationTableModel() {
        }
        
        public String getColumnName(int column) {
            if (column < columnNames.length) {
                return columnNames[column];
            }
            return "";
        }
        
        public synchronized int getColumnCount() {
            return columnNames.length;
        }
        
        public synchronized int getRowCount() {
            return _conversationList.size();
        }
        
        public synchronized Object getValueAt(int row, int column) {
            if (row<0 || row >= _conversationList.size()) {
                System.err.println("Attempt to get row " + row + ", column " + column + " : row does not exist!");
                return null;
            }
            Conversation c = (Conversation) _conversationList.get(row);
            if (column <= columnNames.length) {
                return c.getProperty(columnNames[column].toUpperCase());
            } else {
                System.err.println("Attempt to get row " + row + ", column " + column + " : column does not exist!");
                return null;
            }
        }
    }
    

}
