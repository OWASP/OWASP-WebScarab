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
import org.owasp.webscarab.model.URLTreeModel;
import org.owasp.webscarab.util.MappedListModel;

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

import javax.swing.ListModel;

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
    
    private MappedListModel _unseenLinks = new MappedListModel();
    private TreeMap _seenLinks = new TreeMap();
    
    private Vector _requestQueue = new Vector();
    private Vector _responseQueue = new Vector();
    private Vector _linkQueue = new Vector();
    
    private AsyncFetcher[] _fetchers;
    private int _threads = 4;
    private boolean _recursive = false;
    private boolean _cookieSync = true;
    
    private String _allowedDomains = null;
    private String _forbiddenPaths = null;
    
    private URLTreeModel _unseenLinkTreeModel = new URLTreeModel();
    
    private SpiderStore _store = null;
    
    private CookieJar _cookieJar;
    
    /** Creates a new instance of Spider */
    public Spider(Plug plug) {
        _plug = plug;
        _cookieJar = plug.getCookieJar();
        
        setDefaultProperty("Spider.domains", ".*localhost.*");
        setDefaultProperty("Spider.excludePaths", "");
        setDefaultProperty("Spider.synchroniseCookies","yes");
        setDefaultProperty("Spider.recursive","no");
        parseProperties();
        
        Thread me = new Thread(this);
        me.setDaemon(true);
        me.setPriority(Thread.MIN_PRIORITY);
        me.setName("Spider");
        me.start();
        System.err.println("Spider initialised");
    }
    
    public void parseProperties() {
        String prop = "Spider.domains";
        String value = _prop.getProperty(prop);
        if (value == null) value = "";
        setAllowedDomains(value);
        
        prop = "Spider.excludePaths";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setForbiddenPaths(value);
        
        prop = "Spider.synchroniseCookies";
        value = _prop.getProperty(prop);
        setCookieSync(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
        
        prop = "Spider.recursive";
        value = _prop.getProperty(prop);
        setRecursive(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Spider");
    }
    
    public void run() {
        _fetchers = new AsyncFetcher[_threads];
        for (int i=0; i<_threads; i++) {
            _fetchers[i] = new AsyncFetcher(_requestQueue, _responseQueue, "Spider-" + Integer.toString(i));
        }
        Request request;
        Response response;
        Conversation conversation;
        while (true) {
            
            // if the request queue is empty, add the latest cookies etc to the
            // request and submit it
            synchronized (_linkQueue) {
                if (_linkQueue.size() > 0 && _requestQueue.size() == 0) {
                    Link link = (Link) _linkQueue.remove(0);
                    if (link != null) {
                        System.out.println(_linkQueue.size() + " remaining, queueing " + link.getURL());
                        request = newGetRequest(link);
                        if (request != null) {
                            if (_cookieSync) {
                                _cookieJar.addRequestCookies(request);
                            }
                            // we should set the UserAgent, Accept headers, etc
                            synchronized(_requestQueue) {
                                _requestQueue.add(request);
                            }
                        }
                    }
                }
            }
            
            // see if there are any responses waiting for us
            try {
                synchronized (_responseQueue) {
                    response = (Response) _responseQueue.remove(0);
                }
                if (response != null) {
                    request = response.getRequest();
                    if (request != null) {
                        _plug.addConversation("Spider", request, response);
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
    
    public void requestLinksUnder(String root) {
        synchronized(_unseenLinks) {
            Iterator it = _unseenLinks.keySet().iterator();
            while (it.hasNext()) {
                String url = (String) it.next();
                if (url.startsWith(root)) {
                    if (!forbiddenPath(url)) {
                        Link link = (Link) _unseenLinks.get(url);
                        queueLink(link);
                    } else {
                        System.out.println(url + " is a forbidden path!");
                    }
                }
            }
        }
    }
    
    private void queueLink(Link link) {
        synchronized (_linkQueue) {
            _linkQueue.add(link);
        }
    }
    
    /** removes all pending reuqests from the queues - effectively stops the spider */
    public void resetRequestQueue() {
        synchronized(_linkQueue) {
            _linkQueue.clear();
        }
        synchronized(_requestQueue) {
            _requestQueue.clear();
        }
    }
    
    public void requestLinks(String[] urls) {
        Link link;
        for (int i=0; i<urls.length; i++) {
            link = (Link) _unseenLinks.get(urls[i]);
            if (link != null) {
                queueLink(link);
            } else {
                System.err.println("'" + urls[i] + "' not found");
            }
        }
    }
    
    public void setRecursive(boolean bool) {
        _recursive = bool;
        String prop = "Spider.recursive";
        setProperty(prop,Boolean.toString(bool));
    }
    
    public boolean getRecursive() {
        return _recursive;
    }
    
    public void setCookieSync(boolean enabled) {
        _cookieSync = enabled;
        String prop = "Spider.synchroniseCookies";
        setProperty(prop,Boolean.toString(enabled));
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
        URL referer = request.getURL();
        synchronized (_unseenLinks) {
            String refstr = URLUtil.schemeAuthPathQry(referer);
            if (_unseenLinks.containsKey(refstr)) {
                int index = _unseenLinks.indexOf(refstr);
                _unseenLinks.remove(refstr);
                _unseenLinkTreeModel.remove(refstr);
            }
            _seenLinks.put(refstr,""); // actual value is irrelevant, could be a sequence no, for amusement
        }
        if (response.getStatus().equals("302")) {
            String location = response.getHeader("Location");
            if (location != null) {
                try {
                    URL url = new URL(location);
                    addUnseenLink(url, referer);
                } catch (MalformedURLException mue) {
                    System.err.println("Badly formed Location header : " + location);
                }
            } else {
                System.err.println("302 received, but no Location header!");
            }
            return;
        }
        if (parsed != null && parsed instanceof NodeList) { // the parsed content is HTML
            NodeList nodelist = (NodeList) parsed;
            recurseHtmlNodes(nodelist, referer);
        } // else maybe it is a parsed Flash document? Anyone? :-)
    }
    
    private void recurseHtmlNodes(NodeList nodelist, URL referer) {
        try {
            for (NodeIterator ni = nodelist.elements(); ni.hasMoreNodes();) {
                Node node = ni.nextNode();
                if (node instanceof LinkTag) {
                    LinkTag linkTag = (LinkTag) node;
                    if (! linkTag.isHTTPLikeLink() )
                        continue;
                    String link = linkTag.getLink();
                    if (link == null || link.startsWith("irc://")) // for some reason the htmlparser thinks IRC:// links are httpLike()
                        continue;
                    try {
                        URL url = new URL(link);
                        addUnseenLink(url, referer);
                    } catch (MalformedURLException mue) {
                        System.err.println("Malformed link : " + link);
                    }
                } else if (node instanceof CompositeTag) {
                    CompositeTag ctag = (CompositeTag) node;
                    recurseHtmlNodes(ctag.getChildren(), referer);
                } else if (node instanceof Tag) { // this is horrendous! Why is this not a FrameTag?!
                    Tag tag = (Tag) node;
                    if (tag.getTagName().equals("FRAME")) {
                        String src = tag.getAttribute("src");
                        if (src.startsWith("http:") || src.startsWith("https://")) {
                            try {
                                URL url = new URL(src);
                                addUnseenLink(url, referer);
                            } catch (MalformedURLException mue) {
                                System.err.println("Malformed Frame src : " + src);
                            }
                        } else if (!src.startsWith("about:")) {
                            System.err.println("Creating a new relative URL with " + referer.toString() + " and " + src + " '");
                            try {
                                URL url = new URL(referer, src);
                                addUnseenLink(url, referer);
                            } catch (MalformedURLException mue) {
                                System.out.println("Bad relative URL (" + referer.toString() + ") : " + src);
                            }
                        }
                    }
                }
            }
        } catch (ParserException pe) {
            System.err.println("ParserException : " + pe);
        }
    }
    
    private void addUnseenLink(URL url, URL referer) {
        if (url == null) {
            return;
        }
        synchronized (_unseenLinks) {
            String urlstr = URLUtil.schemeAuthPathQry(url);
            if (!_seenLinks.containsKey(urlstr) && !_unseenLinks.containsKey(urlstr)) {
                Link link = new Link(url, referer);
                _unseenLinks.put(urlstr, link);
                _unseenLinkTreeModel.add(urlstr);
                if (_recursive && allowedURL(url)) {
                    queueLink(link);
                }
            }
        }
    }
    
    private Request newGetRequest(Link link) {
        return newGetRequest(link.getURL(), link.getReferer());
    }
    
    private Request newGetRequest(URL url, URL referer) {
        Request req = new Request();
        req.setMethod("GET");
        req.setURL(url);
        req.setVersion("HTTP/1.0"); // 1.1 or 1.0?
        if (referer != null) {
            req.setHeader("Referer", referer.toString());
        }
        req.setHeader("Host", url.getHost() + ":" + Integer.toString(url.getPort() > -1 ? url.getPort() : url.getDefaultPort()) );
        req.setHeader("Connection", "Keep-Alive");
        return req;
    }
    
    private boolean allowedURL(URL url) {
        // check here if it is on the primary site, or sites, or matches an exclude Regex
        // etc
        // This only applies to the automated recursive spidering. If the operator
        // really wants to fetch something offsite, more power to them
        // Yes, this is effectively the classifier from websphinx, we can use that if it fits nicely
        
        // OK if the URL matches the domain
        if (allowedDomain(url) && !forbiddenPath(url)) {
            return true;
        }
        return false;
    }
    
    public boolean allowedDomain(String url) {
        try {
            return allowedDomain(new URL(url));
        } catch (MalformedURLException mue) {
            System.err.println("Malformed URL : " + url);
            return false;
        }
    }
    
    public boolean allowedDomain(URL url) {
        if (_allowedDomains!= null && !_allowedDomains.equals("") && url.getHost().matches(_allowedDomains)) {
            return true;
        }
        return false;
    }
    
    public boolean forbiddenPath(String url) {
        try {
            return forbiddenPath(new URL(url));
        } catch (MalformedURLException mue) {
            System.err.println("Malformed URL : " + url);
            return true;
        }
    }
    
    public boolean forbiddenPath(URL url) {
        if (_forbiddenPaths != null && !_forbiddenPaths.equals("") && url.getPath().matches(_forbiddenPaths)) {
            return true;
        }
        return false;
    }
    
    public void setAllowedDomains(String regex) {
        _allowedDomains = regex;
        String prop = "Spider.domains";
        setProperty(prop,regex);
    }
    
    public String getAllowedDomains() {
        return _allowedDomains;
    }
    
    public void setForbiddenPaths(String regex) {
        _forbiddenPaths = regex;
        String prop = "Spider.excludePaths";
        setProperty(prop,regex);
    }
    
    public String getForbiddenPaths() {
        return _forbiddenPaths;
    }
    
    public ListModel getUnseenLinkList() {
        return _unseenLinks;
    }
    
    public TreeModel getUnseenLinkTreeModel() {
        return _unseenLinkTreeModel;
    }
    
    public void setSessionStore(Object store) throws StoreException {
        if (store != null && store instanceof SpiderStore) {
            _store = (SpiderStore) store;
            synchronized (_unseenLinks) {
                _unseenLinkTreeModel.clear(); // this fires its own events
                _unseenLinks.clear();
                Link[] links = _store.readUnseenLinks();
                for (int i=0; i<links.length; i++) {
                    String urlstr = URLUtil.schemeAuthPathQry(links[i].getURL());
                    _unseenLinks.put(urlstr,links[i]);
                    _unseenLinkTreeModel.add(urlstr);
                }
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
    
    private String canonicalURL(String url) {
        try {
            URL u = new URL(url);
            url = URLUtil.schemeAuthPathQry(u);
            if (u.getPath().equals("")) {
                url=url+"/";
            }
        } catch (MalformedURLException mue) {
            System.err.println("Malformed url '" + url + "' : " + mue);
            return null;
        }
        return url;
    }
        
}
