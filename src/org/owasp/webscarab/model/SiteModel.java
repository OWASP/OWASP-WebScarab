package org.owasp.webscarab.model;

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
    private SequencedTreeMap _requestCache; // maintains a list of cached Requests
    private SequencedTreeMap _responseCache; // maintains a list of cached Responses
    
    private Map _urlinfo;              // maps urls to attrs
    private int _cachesize = 10;
    
    private Logger logger = Logger.getLogger("WebScarab");
    
    private ConversationTableModel _ctm = new ConversationTableModel();
    
    // the number of Requests and Responses to keep in memory at once. 
    // This includes the complete Request and Response objects, so don't make it too large.
    private static int CONVERSATIONCACHESIZE = 10;
    
    /**
     *  Constructor
     */
    public SiteModel() {
        _conversationList = new SequencedTreeMap();
        _urlinfo = Collections.synchronizedMap(new TreeMap());
        _requestCache = new SequencedTreeMap();
        _responseCache = new SequencedTreeMap();
    } // constructor SiteModel
    
    /** Initialises the lists of conversations, URLInfos, etc */
    public void clearSession() {
        // clear the conversation list
        _conversationList.clear();
        // clear the Request and Response cache
        _requestCache.clear();
        _responseCache.clear();
        // clear the conversationtablemodel
        _ctm.fireTableDataChanged();
        // clear the URLInfo.
        _urlinfo.clear();
    }
    
    // returns the conversation ID
    public String addConversation(Conversation conversation) {
        String id;
        synchronized (_conversationList) {
            id = Integer.toString(_conversationList.size()+1); // FIXME!! Don't use size here!
            _conversationList.put(id, conversation);
            int row = _conversationList.size();
            _ctm.fireTableRowsInserted(row, row);
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
                // this should always return here, since we cache all the 
                // conversations in memory
                return (Conversation) _conversationList.get(id);
            }
        }
        return null;
    }
    
    public void setRequest(String id, Request request) {
        synchronized (_requestCache) {
            if (_requestCache.size() > CONVERSATIONCACHESIZE) {
                _requestCache.remove(0);
            }
            _requestCache.put(id, request);
        }
    }
    
    public Request getRequest(String id) {
        return (Request) _requestCache.get(id);
    }
    
    public void setResponse(String id, Response response) {
        synchronized (_responseCache) {
            if (_responseCache.size() > CONVERSATIONCACHESIZE) {
                _responseCache.remove(0);
            }
            _responseCache.put(id, response);
        }
    }
    
    public Response getResponse(String id) {
        return (Response) _responseCache.get(id);
    }
    
    public URLInfo getURLInfo(String url) {
        URLInfo ui;
        synchronized (_urlinfo) {
            ui = (URLInfo) _urlinfo.get(url);
            if (ui == null) {
                ui = new URLInfo(url);
                _urlinfo.put(url, ui);
            }
        }
        return ui;
    }
    
    public TableModel getConversationTableModel() {
        return _ctm;
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
                if (column == 0) {
                    return new Integer(row+1).toString();
                } else {
                    return c.getProperty(columnNames[column].toUpperCase());
                }
            } else {
                System.err.println("Attempt to get row " + row + ", column " + column + " : column does not exist!");
                return null;
            }
        }
    }
    
}
