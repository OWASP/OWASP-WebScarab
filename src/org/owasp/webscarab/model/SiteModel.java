package src.org.owasp.webscarab.model;

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

/** Model represents the most significant part of the Exodus system. It contains the
 * conversations, as well as the information about all the URLs that have been
 * seen. It is created as an Observable object, so that plugins can be notified of
 * any new Conversations, or URLInfos.
 */
public class SiteModel {
    
    private Map conversation;         // records all the conversations seen.
    private ArrayList conversationList;  // maintains a FIFO list of cached conversations
    private ArrayList _conversationData = new ArrayList(1);  // Keeps the conversation data, is referenced by the ConversationTableModel
    private Map urlinfo;              // maps urls to attrs
    private ArrayList changed = new ArrayList(1);
    private int _cachesize = 10;
    
    private Logger logger = Logger.getLogger("WebScarab.Model");
    
    private ConversationTableModel _ctm = new ConversationTableModel();
    
    /**
     *  Constructor
     */
    public SiteModel() {
        conversation = Collections.synchronizedMap(new TreeMap());
        conversationList = new ArrayList(1);
        urlinfo = Collections.synchronizedMap(new TreeMap());
    } // constructor Model
    
    /** Initialises the lists of conversations, URLInfos, etc */
    public void clearSession() {
        // clear the conversation cache
        conversation.clear();
        conversationList.clear();
        // clear the conversationtablemodel
        _conversationData.clear();
        _ctm.fireTableDataChanged();
        // clear the URLInfo. Will go away when the site tree model is finished?
        urlinfo.clear();
    }
    
    private String currentConversationID = "00000";
    
    private synchronized String getNextConversationID() {
        String id;
        // increment the current id
        currentConversationID = String.valueOf(Integer.parseInt(currentConversationID)+1);
        for (int i=currentConversationID.length(); i<5; i++) {
            currentConversationID = "0" + currentConversationID;
        }
        return currentConversationID;
    }
    
    public void setConversationID(String id) {
        if (Integer.parseInt(id) > Integer.parseInt(currentConversationID)) {
            currentConversationID = id;
        }
    }
    
    public String addConversation(Conversation conversation) {
        String id = getNextConversationID();
        cacheConversation(id, conversation);
        parseResponse(conversation);
        return id;
    }
    
    private void parseResponse(Conversation conversation) {
    }
    
    private void cacheConversation(String conversationID, Conversation c) {
        if (!conversationList.contains(conversationID)) {
            if (_cachesize > 0 && conversationList.size()>=_cachesize) {
                String id = (String) conversationList.remove(0);
                conversation.remove(id);
            }
            conversationList.add(conversationID);
            conversation.put(conversationID, c);
        } // else it is already cached
    }
    
    /** Given a conversation id, returns the corresponding Conversation
     * @return the requested Conversation, or null if it does not exist
     * @param id the requested "opaque" conversation id
     */
    private Conversation getConversation(String id) {
        synchronized (conversation) {
            if (conversation.containsKey(id)) { // if we have it, return it
                conversationList.remove(id); // move it to the end
                conversationList.add(id);
                return (Conversation)conversation.get(id);
                
            /* } else if (backingStore != null) { // if we can get it, cache it
                Conversation c = backingStore.readConversation(id);
                if (c!=null) {
                    cacheConversation(id,c);
                }
                return c;
             */
            } else {  // sorry!
                return null;
            }
        }
    }
    
    public URLInfo getURLInfo(Conversation conversation) {
        String url = conversation.getProperty("URL");
        URLInfo ui;
        synchronized (urlinfo) {
            ui = (URLInfo) urlinfo.get(url);
            if (ui == null) {
                ui = new URLInfo(url);
                urlinfo.put(url, ui);
            }
        }
        synchronized (ui) {
            ui.setProperty("METHOD", conversation.getProperty("METHOD")); // should add it, so as not to override previous
            ui.setProperty("STATUS", conversation.getProperty("STATUS")); // should add it, so as not to override previous
            ui.setProperty("CHECKSUM", conversation.getProperty("CHECKSUM")); // should add it, so as not to override previous
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
    
    
    public TableModel getConversationTableModel() {
        return _ctm;
    }
    
    public class ConversationTableModel extends AbstractTableModel {
        
        public static final int ID = 0;
        public static final int METHOD = 1;
        public static final int SHPP = 2;
        public static final int QUERY = 3;
        public static final int COOKIE = 4;
        public static final int CONTENT = 5;
        public static final int STATUS = 6;
        public static final int SETCOOKIE = 7;
        public static final int CHECKSUM = 8;
        public static final int COMMENT = 9;
        public static final int ORIGIN = 10;
        
        protected String [] columnNames = {
            "ID", "Method", "Path", "Query",
            "Cookies", "Content", "Status",
            "Set-Cookie", "Checksum", "Comment",
            "Origin"
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
            return _conversationData.size();
        }
        
        public synchronized Object getValueAt(int row, int column) {
            if (row<0 || row >= _conversationData.size()) {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            }
            String[] rowdata = (String[]) _conversationData.get(row);
            if (column <= columnNames.length) {
                return rowdata[column];
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            }
        }
    }
    
}
