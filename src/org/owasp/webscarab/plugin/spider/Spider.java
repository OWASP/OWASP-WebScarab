/*
 * Spider.java
 *
 * Created on August 5, 2003, 10:52 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;
import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.htmlparser.Node;

import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.CompositeTag;

import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import java.util.logging.Logger;
import java.util.Vector;
import java.util.NoSuchElementException;
import java.util.TreeMap;

import java.net.MalformedURLException;

import java.lang.Thread;
import java.lang.Runnable;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

/**
 *
 * @author  rdawes
 */

public class Spider extends AbstractWebScarabPlugin implements Runnable {
    
    private Plug _plug;
    private Logger _logger = Logger.getLogger("Plug.Spider");
    
    private SequencedTreeMap _unseenLinks = new SequencedTreeMap();
    private TreeMap _seenLinks = new TreeMap();
    
    private Vector _requestQueue = new Vector();
    private Vector _responseQueue = new Vector();
    
    private AsyncFetcher[] _fetchers;
    private int _threads = 4;
    private boolean _recursive = false;
    
    private UnseenLinkTableModel _unseenLinkTableModel = new Spider.UnseenLinkTableModel();
    
    /** Creates a new instance of Spider */
    public Spider(Plug plug) {
        _plug = plug;

        _logger.info("Spider initialised");
        Thread me = new Thread(this);
        me.setDaemon(true);
        me.start();
    }
    
    public String getPluginName() {
        return new String("Spider");
    }
    
    public void run() {
        _fetchers = new AsyncFetcher[_threads];
        for (int i=0; i<_threads; i++) {
            _fetchers[i] = new AsyncFetcher(_requestQueue, _responseQueue);
        }
        Request request;
        Response response;
        Conversation conversation;
        while (true) {
            try {
                response = (Response) _responseQueue.firstElement();
                if (response != null) {
                    request = response.getRequest();
                    if (request != null) {
                        conversation = new Conversation(request, response);
                        _plug.addConversation(conversation);
                    }
                }
            } catch (NoSuchElementException nsee) {
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
    }
    
    private void queueRequest(Request request) {
        // add cookies, etc
        // set the UserAgent, Accept headerss, etc
        _requestQueue.add(request);
    }
    
    /** removes all pending reuqests from the queue - effectively stops the spider */
    public void resetRequestQueue() {
        _requestQueue.clear();
    }
    
    public void requestURLs(String[] urls) {
        Request req;
        for (int i=0; i<urls.length; i++) {
            req = (Request) _unseenLinks.get(urls[i]);
            if (req != null) {
                queueRequest(req);
            }
        }
    }
    
    public void setRecursive(boolean recursive) {
        _recursive = recursive;
    }
    
    public boolean getRecursive() {
        return _recursive;
    }
    
    /** Called by the WebScarab data model once the {@link Response} has been parsed. It
     * is called for all Conversations seen by the model (submitted by all plugins, not
     * just this one).
     * Any information gathered by this module should also be summarised into the
     * supplied URLInfo, since only this analysis procedure will know how to do so!
     * @param conversation The parsed Conversation to be analysed.
     * @param urlinfo The class instance that contains the summarised information about this
     * particular URL
     */
    public synchronized void analyse(Conversation conversation, URLInfo urlinfo) {
        String referer = conversation.getRequest().getURL().toString();
        synchronized (_unseenLinks) {
            if (_unseenLinks.containsKey(referer)) {
                int index = _unseenLinks.indexOf(referer);
                _unseenLinks.remove(referer);
                _unseenLinkTableModel.fireTableRowsDeleted(index, index);
            }
            _seenLinks.put(referer,""); // actual value is irrelevant, could be a sequence no, for amusement
            _logger.info("adding " + referer + " to the seen list");
        }
        NodeList nodelist = conversation.getNodeList();
        if (nodelist == null) return; // FIXME : also handle 302 redirects, etc
        recurseNodes(nodelist, referer);
    }
    
    private void recurseNodes(NodeList nodelist, String referer) {
        try {
            for (NodeIterator ni = nodelist.elements(); ni.hasMoreNodes();) {
                Node node = ni.nextNode();
                if (node instanceof LinkTag) {
                    LinkTag linkTag = (LinkTag) node;
                    if (! linkTag.isHTTPLikeLink() ) 
                        continue;
                    String url = linkTag.getLink();
                    if (url.startsWith("irc://")) // for some reason the htmlparser thinks IRC:// links are httpLike()
                        continue;
                    synchronized (_unseenLinks) {
                        if (!_seenLinks.containsKey(url) && !_unseenLinks.containsKey(url)) {
                            Request request = newGetRequest(url, referer);
                            _unseenLinks.put(url, request);
                            int index = _unseenLinks.size()-1;
                            _unseenLinkTableModel.fireTableRowsInserted(index, index);
                            // _logger.info("Adding " + url + " to the unseen list");
                            if (_recursive && allowedURL(url)) {
                                queueRequest(request);
                            }
                        }
                    }
                } else if (node instanceof CompositeTag) {
                    CompositeTag ctag = (CompositeTag) node;
                    recurseNodes(ctag.getChildren(), referer);
                }
            }
        } catch (ParserException pe) {
            _logger.severe("ParserException : " + pe);
        }
    }        

    private synchronized Request newGetRequest(String url, String referer) {
        Request req = new Request();
        req.setMethod("GET");
        try {
            req.setURL(url);
        } catch (MalformedURLException mue) {
            _logger.severe("Invalid URL '" + url + "' : " + mue);
            return null;
        }
        req.setVersion("HTTP/1.0"); // 1.1 or 1.0?
        if (referer != null) {
            req.setHeader("Referer", referer);
        }
        return req;
    }
    
    private boolean allowedURL(String url) {
        // check here if it is on the primary site, or sites, or matches an exclude Regex
        // etc
        // This only applies to the automated recursive spidering. If the operator
        // really wants to fetch something offsite, more power to them
        // Yes, this is effectively the classifier from websphinx, we can use that if it fits nicely
        return false;
    }
    
    public TableModel getUnseenLinkTableModel() {
        return _unseenLinkTableModel;
    }
    
    private class UnseenLinkTableModel extends AbstractTableModel {
    
        protected String [] columnNames = {
            "ID", "URL", "Referer", "Link source"
        };
        
        public String getColumnName(int column) {
            if (column < columnNames.length) {
                return columnNames[column];
            }
            return "";
        }
        
        public synchronized int getColumnCount() {
            return columnNames.length;
        }
        
        public int getRowCount() {
            return _unseenLinks.size();
        }
        
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex <0 || rowIndex >= getRowCount()) {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + rowIndex + ", column " + columnIndex + " : row does not exist!");
            }
            Request req = (Request) _unseenLinks.get(rowIndex);
            if (columnIndex <= columnNames.length) {
                switch (columnIndex) {
                    case 0 : return new Integer(rowIndex+1).toString();
                    case 1 : return req.getURL().toString();
                    case 2 : return req.getHeader("Referer");
                }
                return "";
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + rowIndex + ", column " + columnIndex + " : column does not exist!");
            }
        }
        
    }
}
