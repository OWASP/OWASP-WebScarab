package org.owasp.webscarab.model;

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
    
    private ArrayList _conversationList;  // maintains a FIFO list of cached conversations
    private Map _urlinfo;              // maps urls to attrs
    private int _cachesize = 10;
    
    private Logger logger = Logger.getLogger("WebScarab.Model");
    
    private ConversationTableModel _ctm = new ConversationTableModel();
    
    /**
     *  Constructor
     */
    public SiteModel() {
        _conversationList = new ArrayList(1);
        _urlinfo = Collections.synchronizedMap(new TreeMap());
    } // constructor Model
    
    /** Initialises the lists of conversations, URLInfos, etc */
    public void clearSession() {
        // clear the conversation list
        _conversationList.clear();
        // clear the conversationtablemodel
        _ctm.fireTableDataChanged();
        // clear the URLInfo.
        _urlinfo.clear();
    }
    
    public String addConversation(Conversation conversation) {
        logger.info("Entering model's addConversation");
        _conversationList.add(conversation);
        int row = _conversationList.size();
        _ctm.fireTableRowsInserted(row, row);
        logger.info("Cached the conversation");
        parseResponse(conversation);
        logger.info("parsed the response");
        return Integer.toString(_conversationList.size());
    }
    
    private void parseResponse(Conversation conversation) {
        String ct = conversation.getResponse().getHeader("Content-Type");
        if (ct != null && ct.startsWith("text/html")) {
            // HTMLParser hp = new HTMLParser()
            // hp.parse(conversation);
        }
        logger.info("parsed response");
    }
    
    /** Given a conversation id, returns the corresponding Conversation
     * @return the requested Conversation, or null if it does not exist
     * @param id the requested "opaque" conversation id
     */
    public Conversation getConversation(String id) {
        try {
            int pos = Integer.parseInt(id)-1;
            synchronized (_conversationList) {
                if (_conversationList.size()>pos) {
                    return (Conversation) _conversationList.get(pos);
                } else {
                    throw new ArrayIndexOutOfBoundsException("ID " + id + " is out of bounds");
                }
            }
        } catch (NumberFormatException nfe) {
            return null;
        }
    }
    
    public URLInfo createURLInfo(Conversation conversation) {
        String url = conversation.getProperty("URL");
        URLInfo ui;
        synchronized (_urlinfo) {
            ui = (URLInfo) _urlinfo.get(url);
            if (ui == null) {
                ui = new URLInfo(url);
                _urlinfo.put(url, ui);
            }
        }
        synchronized (ui) {
            String property = "METHOD";
            String value = conversation.getProperty(property);
            if (value != null) ui.setProperty(property, value); // should add it, so as not to override previous

            property = "STATUS";
            value = conversation.getProperty(property);
            if (value != null) ui.setProperty(property, value); // should add it, so as not to override previous

            property = "CHECKSUM";
            value = conversation.getProperty(property);
            if (value != null) ui.setProperty(property, value); // should add it, so as not to override previous
            
            int conversationbytes = 0;
            int urlbytes = 0;
            try {
                String total = ui.getProperty("TOTALBYTES");
                if (total != null) {
                    urlbytes = Integer.parseInt(total);
                }
                String size = conversation.getProperty("SIZE");
                if (size != null) {
                    conversationbytes = Integer.parseInt(size);
                }
            } catch (NumberFormatException nfe) {
                System.out.println("NumberFormat Exception : " + nfe);
            }
            ui.setProperty("TOTALBYTES", Integer.toString(urlbytes+conversationbytes));
            
            // should add it, so as not to override previous. This should not really be a Boolean, 
            // rather a list of the cookies, it is difficult to concatenate a list of Set-Cookies, though :-(
            ui.setProperty("SET-COOKIE", Boolean.toString(conversation.getProperty("SET-COOKIE")!=null)); 
            
        }        
        return ui;
    }
    
    public URLInfo getURLInfo(String url) {
        URLInfo ui;
        synchronized (_urlinfo) {
            ui = (URLInfo) _urlinfo.get(url);
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
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            }
            Conversation c = (Conversation) _conversationList.get(row);
            if (column <= columnNames.length) {
                if (column == 0) {
                    return new Integer(row+1).toString();
                } else {
                    return c.getProperty(columnNames[column].toUpperCase());
                }
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            }
        }
    }
    
}
