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
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.CookieJar;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;
import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.htmlparser.Node;

import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.CompositeTag;
import org.htmlparser.tags.FrameSetTag;
import org.htmlparser.tags.Tag;

import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import java.util.logging.Logger;
import java.util.Vector;
import java.lang.ArrayIndexOutOfBoundsException;
import java.util.TreeMap;
import java.util.Map;
import java.util.Collections;
import java.util.Iterator;

import java.net.URL;
import java.net.MalformedURLException;

import java.lang.Thread;
import java.lang.Runnable;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import javax.swing.tree.TreeModel;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;

import org.owasp.util.URLUtil;

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
    private boolean _cookieSync = true;
    
    private String _allowedDomains = ".*localhost.*";
    private String _forbiddenPaths = "";
    
    private UnseenLinkTableModel _unseenLinkTableModel = new Spider.UnseenLinkTableModel();
    
    private SpiderStore _store = null;
    
    private CookieJar _cookieJar;
    
    /** Creates a new instance of Spider */
    public Spider(Plug plug) {
        _plug = plug;
        _cookieJar = plug.getCookieJar();
        
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
                response = (Response) _responseQueue.remove(0);
                if (response != null) {
                    request = response.getRequest();
                    if (request != null) {
                        _plug.addConversation(request, response);
                        if (_cookieSync) {
                            _cookieJar.updateCookies(response);
                        }
                    }
                }
            } catch (ArrayIndexOutOfBoundsException aioob) {
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
    }
    
    private void queueRequest(Request request) {
        // FIXME!
        // we need to be more careful about adding requests to the queue.
        // if we get cookies back, we want to be able to add them to following
        // requests. The way we do it currently, those requests are already 
        // queued, most likely :-(
        //
        // We could probably do that in the main run() loop, rather. Add the requests 
        // to a local queue, and as we get responses from the AsyncFetchers, remove 
        // pending requests, update the Cookies, and queue them to the AsyncFetchers.
        //
        if (_cookieSync) {
            _cookieJar.addRequestCookies(request);
        }
        // set the UserAgent, Accept headerss, etc
        _requestQueue.add(request);
    }
    
    /** removes all pending reuqests from the queue - effectively stops the spider */
    public void resetRequestQueue() {
        _logger.info("Clearing request queue");
        _requestQueue.clear();
    }
    
    public void requestURLs(String[] urls) {
        Request req;
        Link link;
        for (int i=0; i<urls.length; i++) {
            link = (Link) _unseenLinks.get(urls[i]);
            if (link != null) {
                req = newGetRequest(link);
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
    
    public void setCookieSync(boolean enabled) {
        _cookieSync = enabled;
    }
    
    public boolean getCookieSync() {
        return _cookieSync;
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
    public synchronized void analyse(Request request, Response response, Conversation conversation, URLInfo urlinfo, Object parsed) {
        String referer = request.getURL().toString();
        synchronized (_unseenLinks) {
            if (_unseenLinks.containsKey(referer)) {
                int index = _unseenLinks.indexOf(referer);
                _unseenLinks.remove(referer);
                synchronized (_unseenLinkTableModel) {
                    _unseenLinkTableModel.fireTableRowsDeleted(index, index);
                }
            }
            _seenLinks.put(referer,""); // actual value is irrelevant, could be a sequence no, for amusement
        }
        if (response.getStatus().equals("302")) {
            addUnseenLink(response.getHeader("Location"), referer);
            return;
        }
        if (parsed != null && parsed instanceof NodeList) { // the parsed content is HTML
            NodeList nodelist = (NodeList) parsed;
            recurseHtmlNodes(nodelist, referer);
        } // else maybe it is a parsed Flash document? Anyone? :-)
    }
    
    private void recurseHtmlNodes(NodeList nodelist, String referer) {
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
                    addUnseenLink(url, referer);
                } else if (node instanceof CompositeTag) {
                    CompositeTag ctag = (CompositeTag) node;
                    recurseHtmlNodes(ctag.getChildren(), referer);
                } else if (node instanceof Tag) { // this is horrendous! Why is this not a FrameTag?!
                    Tag tag = (Tag) node;
                    if (tag.getTagName().equals("FRAME")) {
                        String url = tag.getAttribute("src");
                        if (url.startsWith("http:") || url.startsWith("https://")) {
                            addUnseenLink(url, referer);
                        } else if (!url.startsWith("about:")) {
                            // eeeww! icky!
                            try {
                                addUnseenLink(new URL(new URL(referer), url).toString(), referer);
                            } catch (MalformedURLException mue) {
                                System.out.println("Bad URL " + url);
                            }
                        }
                    }
                }
            }
        } catch (ParserException pe) {
            _logger.severe("ParserException : " + pe);
        }
    }
    
    private void addUnseenLink(String url, String referer) {
        int anchor = url.indexOf("#");
        if (anchor>-1) {
            url = url.substring(0,anchor);
        }
        synchronized (_unseenLinks) {
            if (!_seenLinks.containsKey(url) && !_unseenLinks.containsKey(url)) {
                Link link = new Link(url, referer);
                _unseenLinks.put(url, link);
                int index = _unseenLinks.size()-1;
                synchronized (_unseenLinkTableModel) {
                    _unseenLinkTableModel.fireTableRowsInserted(index, index);
                }
                // _logger.info("Adding " + url + " to the unseen list");
                if (_recursive && allowedURL(url)) {
                    queueRequest(newGetRequest(link));
                }
            }
        }
    }
    
    private Request newGetRequest(Link link) {
        return newGetRequest(link.getURL(), link.getReferer());
    }
    
    private Request newGetRequest(String url, String referer) {
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
        req.setHeader("Connection", "Keep-Alive");
        return req;
    }
    
    private boolean allowedURL(String url) {
        // check here if it is on the primary site, or sites, or matches an exclude Regex
        // etc
        // This only applies to the automated recursive spidering. If the operator
        // really wants to fetch something offsite, more power to them
        // Yes, this is effectively the classifier from websphinx, we can use that if it fits nicely
        
        // OK if the URL matches the domain
        if (_allowedDomains!= null && !_allowedDomains.equals("") && url.matches(_allowedDomains)) {
            // NOT OK if it matches the path
            if (_forbiddenPaths != null && !_forbiddenPaths.equals("") && url.matches(_forbiddenPaths)) {
                return false;
            }
            return true;
        }
        return false;
    }
    
    public void setAllowedDomains(String regex) {
        _allowedDomains = regex;
    }
    
    public String getAllowedDomains() {
        return _allowedDomains;
    }
    
    public void setForbiddenPaths(String regex) {
        _forbiddenPaths = regex;
    }
    
    public String getForbiddenPaths() {
        return _forbiddenPaths;
    }
    
    public TableModel getUnseenLinkTableModel() {
        return _unseenLinkTableModel;
    }
    
    public void setSessionStore(Object store) throws StoreException {
        if (store != null && store instanceof SpiderStore) {
            _store = (SpiderStore) store;
            synchronized (_unseenLinks) {
                _unseenLinks.clear();
                Link[] links = _store.readUnseenLinks();
                for (int i=0; i<links.length; i++) {
                    _unseenLinks.put(links[i].getURL(),links[i]);
                }
                _unseenLinkTableModel.fireTableDataChanged();
                // FIXME : we also need to update the tree here, once it is implemented
            }
            synchronized (_seenLinks) {
                _seenLinks.clear();
                String[] seen = _store.readSeenLinks();
                for (int i=0; i<seen.length; i++) {
                    _seenLinks.put(seen[i], "");
                }
            }
        } else {
            throw new StoreException("object passed does not implement SpiderStore!");
        }
    }
    
    public void saveSessionData() throws StoreException {
        if (_store != null) {
            synchronized (_unseenLinks) {
                Link[] links = new Link[_unseenLinks.size()];
                for (int i=0; i<links.length; i++) {
                    links[i] = (Link) _unseenLinks.get(i);
                }
                _store.writeUnseenLinks(links);
            }
            synchronized (_seenLinks) {
                String[] seen = new String[_seenLinks.size()];
                Iterator keys = _seenLinks.keySet().iterator();
                for (int i=0; i<seen.length; i++) {
                    seen[i] = (String) keys.next();
                }
                _store.writeSeenLinks(seen);
            }
        }
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
            Link link = (Link) _unseenLinks.get(rowIndex);
            if (columnIndex <= columnNames.length) {
                switch (columnIndex) {
                    case 0 : return new Integer(rowIndex+1).toString();
                    case 1 : return link.getURL();
                    case 2 : return link.getReferer();
                    case 3 : return link.getType();
                }
                return "";
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + rowIndex + ", column " + columnIndex + " : column does not exist!");
            }
        }
        
    }
    
    private class UnseenLinkTreeModel extends DefaultTreeModel {
        
        private DefaultTreeModel treeModel;
        private DefaultMutableTreeNode root;
        private Map treeNodes = Collections.synchronizedMap(new TreeMap());
        
        /** Creates a new instance of WebTreeModel */
        public UnseenLinkTreeModel() {
            super(null, true);
            root = new DefaultMutableTreeNode(null);
            super.setRoot(root);
            root.setAllowsChildren(true);
            treeNodes.put("",root);
        }
        
        public void clear() {
            root.removeAllChildren();
        }
        
        protected TreePath addNode(Link link) {
            try {
                URL url = new URL(link.getURL());
                String shpp = URLUtil.schemeAuthPath(url);
                String shp = URLUtil.schemeAuth(url);
                DefaultMutableTreeNode un;
                synchronized (treeNodes) {
                    un = (DefaultMutableTreeNode)treeNodes.get(shpp);
                    if (un != null) {
                        un.setUserObject(link);
                        treeNodes.put(shpp,un);
                        fireTreeNodesChanged(un, un.getPath(), null, null);
                        return new TreePath(un.getPath());
                    }
                }
                
            } catch (MalformedURLException mue) {
                System.err.println("Error creating an URL from '" + link.getURL() + "'");
            }
            //            String shp = link.getURL()
            //            String[] elements = ui.getURLElements();
            //            String path = "";
            //            synchronized (treeNodes) {
            //                DefaultMutableTreeNode parent = root;
            //                for (int i = 0; i<elements.length-1; i++) {
            //                    path = path + elements[i];
            //                    parent = (DefaultMutableTreeNode)treeNodes.get(path);
            //                    if (parent == null) {
            //                        logger.severe("ERROR: an intermediate node was null! path is \"" + path + "\"");
            //                        System.exit(0);
            //                    }
            //                }
            //                path = path + elements[elements.length-1];
            //                un = new DefaultMutableTreeNode(ui);
            //                if (path.endsWith("/")) {
            //                    un.setAllowsChildren(true);
            //                } else {
            //                    un.setAllowsChildren(false);
            //                }
            //                treeNodes.put(path,un);
            //
            //                int numChildren = parent.getChildCount();
            //                if (numChildren == 0) { // this is the first child, just add it
            //                    parent.add(un);
            //                    fireTreeNodesInserted(parent, parent.getPath(), new int[] {numChildren}, new Object[] {un});
            //                } else { // work out where to put it
            //                    DefaultMutableTreeNode node = (DefaultMutableTreeNode)parent.getLastChild();
            //                    URLInfo urlinfo = (URLInfo)node.getUserObject();
            //                    String siblingPath = urlinfo.getURL().toString();
            //                    if (path.compareTo(siblingPath) > 0 ) { // If it is greater than the last node, add it and be done
            //                        parent.add(un);
            //                        fireTreeNodesInserted(parent, parent.getPath(), new int[] {numChildren}, new Object[] {un});
            //                    } else { // work out where to insert it
            //                        for (int i = 0; i<numChildren; i++) {
            //                            node = (DefaultMutableTreeNode)parent.getChildAt(i);
            //                            urlinfo = (URLInfo)node.getUserObject();
            //                            siblingPath = urlinfo.getURL().toString();
            //                            int c = path.compareTo(siblingPath);
            //                            if (c < 0) {
            //                                parent.insert(un,i);
            //                                fireTreeNodesInserted(parent, parent.getPath(), new int[] {i}, new Object[] {un});
            //                                break;
            //                            } else if ( c == 0) {
            //                                break;
            //                            }
            //                        }
            //                    }
            //                }
            //            }
            //            if (un != null) {
            //                return new TreePath(un.getPath());
            //            } else {
            return new TreePath(root);
            //            }
        }
        
    }
    
}
