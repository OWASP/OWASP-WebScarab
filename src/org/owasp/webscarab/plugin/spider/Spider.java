/*
 * Spider.java
 *
 * Created on August 5, 2003, 10:52 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.model.SiteModelAdapter;

import org.owasp.webscarab.parser.Parser;

import org.owasp.webscarab.plugin.Plugin;

import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.htmlparser.Node;

import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.CompositeTag;
import org.htmlparser.tags.Tag;

import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import java.util.Vector;
import java.lang.ArrayIndexOutOfBoundsException;
import java.util.Properties;
import java.util.Date;

import java.util.logging.Logger;

import java.net.MalformedURLException;

import java.lang.Thread;

/**
 *
 * @author  rdawes
 */

public class Spider extends Plugin {
    
    private SiteModel _model = null;
    
    private SpiderUI _ui = null;
    
    private Vector _requestQueue = new Vector();
    private Vector _responseQueue = new Vector();
    private Vector _linkQueue = new Vector();
    private Vector _conversationQueue = new Vector();
    
    private AsyncFetcher[] _fetchers = new AsyncFetcher[0];
    private int _threads = 4;
    private boolean _recursive = false;
    private boolean _cookieSync = true;
    
    private Analyser _analyser;
    
    private String _allowedDomains = null;
    private String _forbiddenPaths = null;
    
    private boolean _stopping = false;
    
    private Listener _listener = null;
    
    private Thread _runThread = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _status = "Stopped";
    
    /** Creates a new instance of Spider */
    public Spider(Properties props) {
        super(props);
        
        parseProperties();
    }
    
    public void setSession(SiteModel model, String type, Object connection) throws StoreException {
        if (_model != null && _listener != null) {
            _model.removeSiteModelListener(_listener);
        }
        _model = model;
        _listener = new Listener();
        _model.addSiteModelListener(_listener);
        if (_ui != null) _ui.setModel(model);
    }
    
    public void setUI(SpiderUI ui) {
        _ui = ui;
        if (_ui != null) _ui.setEnabled(_running);
    }
    
    public void parseProperties() {
        String prop = "Spider.domains";
        String value = _props.getProperty(prop, ".*localhost.*");
        setAllowedDomains(value);
        
        prop = "Spider.excludePaths";
        value = _props.getProperty(prop, "");
        setForbiddenPaths(value);
        
        prop = "Spider.synchroniseCookies";
        value = _props.getProperty(prop, "true");
        setCookieSync(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
        
        prop = "Spider.recursive";
        value = _props.getProperty(prop, "false");
        setRecursive(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Spider");
    }
    
    public void run() {
        _status = "Started";
        _stopping = false;
        _runThread = Thread.currentThread();
        
        // start the analyser thread
        _analyser = new Analyser();
        Thread t = new Thread(_analyser);
        t.setDaemon(true);
        t.setName("Spider-Analyser");
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
        
        // start the fetchers
        _fetchers = new AsyncFetcher[_threads];
        for (int i=0; i<_threads; i++) {
            _fetchers[i] = new AsyncFetcher(_requestQueue, _responseQueue);
            t = new Thread(_fetchers[i], "Spider-" + Integer.toString(i));
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            t.start();
        }
        
        _running = true;
        if (_ui != null) _ui.setEnabled(_running);
        while (!_stopping) {
            // queue them as fast as they come, sleep a bit otherwise
            if (!queueRequests() && !dequeueResponses()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
        for (int i=0; i<_fetchers.length; i++) {
            _fetchers[i].stop();
        }
        _analyser.stop();
        _running = false;
        _runThread = null;
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
    }
    
    private boolean queueRequests() {
        // if the request queue is empty, add the latest cookies etc to the
        // request and submit it
        Link link;
        synchronized (_linkQueue) {
            if (_linkQueue.size() > 0 && _requestQueue.size() == 0) {
                link = (Link) _linkQueue.remove(0);
                _logger.info(_linkQueue.size() + " remaining, queueing " + link.getURL());
                if (_ui != null) _ui.linkDequeued(link);
            } else {
                return false;
            }
        }
        if (link == null) {
            _logger.warning("Got a null link from the link queue");
            return false;
        }
        Request request = newGetRequest(link);
        if (_cookieSync) {
            Cookie[] cookies = _model.getCookiesForUrl(request.getURL());
            if (cookies.length>0) {
                StringBuffer buff = new StringBuffer();
                buff.append(cookies[0].getName()).append("=").append(cookies[0].getValue());
                for (int i=1; i<cookies.length; i++) {
                    buff.append("; ").append(cookies[i].getName()).append("=").append(cookies[i].getValue());
                }
                request.setHeader("Cookie", buff.toString());
            }
        }
        synchronized(_requestQueue) {
            _requestQueue.add(request);
        }
        return true;
    }
    
    private boolean dequeueResponses() {
        // see if there are any responses waiting for us
        Response response;
        synchronized (_responseQueue) {
            if (_responseQueue.size() > 0) {
                response = (Response) _responseQueue.remove(0);
            } else {
                return false;
            }
        }
        if (response == null) {
            _logger.warning("Got a null response from the response queue!");
            return false;
        }
        Request request = response.getRequest();
        if (request == null) {
            _logger.warning("Got a null request from the response!");
            return false;
        }
        _model.addConversation(request, response, "Spider");
        if (_cookieSync) {
            String[][] headers = response.getHeaders();
            for (int i=0; i<headers.length; i++) {
                if (headers[i][0].equals("Set-Cookie") || headers[i][0].equals("Set-Cookie2")) {
                    Cookie cookie = new Cookie(new Date(), request.getURL(), headers[i][1]);
                    _model.addCookie(cookie);
                }
            }
        }
        return true;
    }
    
    public boolean isBusy() {
        if (!_running) return false;
        synchronized(_linkQueue) {
            return _linkQueue.size() > 0 || _analyser.isBusy();
        }
    }
    
    public void requestLinksUnder(HttpUrl url) {
        try {
            _model.readLock().acquire();
            try {
                queueLinksUnder(url);
            } finally {
                _model.readLock().release();
            }
        } catch (InterruptedException ie) {
            _logger.info("Interrupted!");
        }
    }
    
    private void queueLinksUnder(HttpUrl url) {
        Link link;
        // fetch the queries for the url first
        int count = _model.getQueryCount(url);
        for (int i=0; i<count; i++) {
            HttpUrl query = _model.getQueryAt(url, i);
            if (! forbiddenPath(query)) {
                if (_model.getConversationCount(query) == 0) {
                    String referer = _model.getUrlProperty(query, "REFERER");
                    link = new Link(query, referer);
                    queueLink(link);
                }
            } else {
                _logger.warning("Skipping forbidden path " + query);
            }
        }
        // then fetch any child urls
        count = _model.getChildUrlCount(url);
        for (int i=0; i<count; i++) {
            HttpUrl child = _model.getChildUrlAt(url, i);
            queueLinksUnder(child);
            if (_model.getConversationCount(child) == 0) {
                if (! forbiddenPath(child)) {
                    String referer = _model.getUrlProperty(child, "REFERER");
                    link = new Link(child, referer);
                    queueLink(link);
                } else {
                    _logger.warning("Skipping forbidden path " + child);
                }
            }
        }
    }
    
    public void requestLinks(HttpUrl[] urls) {
        Link link;
        for (int i=0; i<urls.length; i++) {
            String referer = _model.getUrlProperty(urls[i], "REFERER");
            link = new Link(urls[i], referer);
            queueLink(link);
        }
    }
    
    private void queueLink(Link link) {
        _logger.info("Queueing " + link);
        synchronized (_linkQueue) {
            _linkQueue.add(link);
        }
        if (_ui != null) _ui.linkQueued(link);
    }
    
    /** removes all pending requests from the queues - effectively stops the spider */
    public void resetRequestQueue() {
        Link link;
        synchronized(_linkQueue) {
            while(_linkQueue.size()>0) {
                link = (Link) _linkQueue.remove(0);
                if (_ui != null) _ui.linkDequeued(link);
            }
        }
        synchronized(_requestQueue) {
            _requestQueue.clear();
        }
    }
    
    public void setRecursive(boolean bool) {
        _recursive = bool;
        String prop = "Spider.recursive";
        _props.setProperty(prop,Boolean.toString(bool));
    }
    
    public boolean getRecursive() {
        return _recursive;
    }
    
    public void setCookieSync(boolean enabled) {
        _cookieSync = enabled;
        String prop = "Spider.synchroniseCookies";
        _props.setProperty(prop,Boolean.toString(enabled));
    }
    
    public boolean getCookieSync() {
        return _cookieSync;
    }
    
    private Request newGetRequest(Link link) {
        HttpUrl url = link.getURL();
        String referer = link.getReferer();
        Request req = new Request();
        req.setMethod("GET");
        req.setURL(url);
        req.setVersion("HTTP/1.0"); // 1.1 or 1.0?
        if (referer != null) {
            req.setHeader("Referer", referer);
        }
        req.setHeader("Host", url.getHost() + ":" + url.getPort());
        req.setHeader("Connection", "Keep-Alive");
        return req;
    }
    
    private boolean allowedURL(HttpUrl url) {
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
    
    private boolean allowedDomain(HttpUrl url) {
        if (_allowedDomains!= null && !_allowedDomains.equals("") && url.getHost().matches(_allowedDomains)) {
            return true;
        }
        return false;
    }
    
    private boolean forbiddenPath(HttpUrl url) {
        if (_forbiddenPaths != null && !_forbiddenPaths.equals("") && url.getPath().matches(_forbiddenPaths)) {
            return true;
        }
        return false;
    }
    
    public void setAllowedDomains(String regex) {
        _allowedDomains = regex;
        String prop = "Spider.domains";
        _props.setProperty(prop,regex);
    }
    
    public String getAllowedDomains() {
        return _allowedDomains;
    }
    
    public void setForbiddenPaths(String regex) {
        _forbiddenPaths = regex;
        String prop = "Spider.excludePaths";
        _props.setProperty(prop,regex);
    }
    
    public String getForbiddenPaths() {
        return _forbiddenPaths;
    }
    
    public void flush() throws StoreException {
        // we do not manage our own store
    }
    
    public boolean stop() {
        if (isBusy()) return false;
        _stopping = true;
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.severe("Interrupted stopping " + getPluginName());
        }
        return !_running;
    }
    
    public String getStatus() {
        if (isBusy()) 
            return "Started, " + 
            _analyser.queueSize() + " queued for analysis, " + 
            _linkQueue.size() + " queued for fetching";
        return _status;
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(ConversationID id) {
            _analyser.queue(id);
        }
        
        public void urlAdded(HttpUrl url) {
            // FIXME TODO We could add something here to support removal of links from
            // the queue, maybe
        }
        
    }
    
    private class Analyser implements Runnable {
        
        private Vector _queue = new Vector(); // is synchronized already
        private boolean _stopping = false;
        private boolean _running = false;
        private Thread _runThread = null;
        
        public void queue(ConversationID id) {
            _queue.add(id);
        }
        
        private int queueSize() {
            return _queue.size();
        }
        
        public boolean isBusy() {
            return _queue.size() > 0;
        }
        
        public void reset() {
            _queue.clear();
        }
        
        public void run() {
            _runThread = Thread.currentThread();
            _stopping = false;
            _running = true;
            while (!_stopping) {
                if (_queue.size()>0) {
                    ConversationID id = (ConversationID) _queue.remove(0);
                    _logger.info("Analysing " + id);
                    analyse(id);
                } else {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException ie) {}
                }
            }
            _running = false;
            _runThread = null;
        }
        
        public boolean stop() {
            if (_running) {
                _stopping = true;
                try {
                    _runThread.join(5000);
                } catch (InterruptedException ie) {
                    _logger.warning("Interrupted!");
                }
            }
            return ! _running;
        }
        
        private void analyse(ConversationID id) {
            Request request = _model.getRequest(id);
            Response response = _model.getResponse(id);
            HttpUrl base = request.getURL();
            if (response.getStatus().equals("302")) {
                String location = response.getHeader("Location");
                if (location != null) {
                    try {
                        HttpUrl url = new HttpUrl(location);
                        addUnseenLink(url, base);
                    } catch (MalformedURLException mue) {
                        _logger.warning("Badly formed Location header : " + location);
                    }
                } else {
                    _logger.warning("302 received, but no Location header!");
                }
                return;
            }
            Object parsed = Parser.parse(base, response);
            if (parsed != null && parsed instanceof NodeList) { // the parsed content is HTML
                NodeList nodelist = (NodeList) parsed;
                recurseHtmlNodes(nodelist, base);
            } // else maybe it is a parsed Flash document? Anyone? :-)
        }
        
        private void recurseHtmlNodes(NodeList nodelist, HttpUrl base) {
            try {
                for (NodeIterator ni = nodelist.elements(); ni.hasMoreNodes();) {
                    Node node = ni.nextNode();
                    if (node instanceof LinkTag) {
                        LinkTag linkTag = (LinkTag) node;
                        if (! linkTag.isHTTPLikeLink() )
                            continue;
                        String link = linkTag.getLink();
                        // for some reason the htmlparser thinks IRC:// links are httpLike
                        if (link == null || link.startsWith("irc://"))
                            continue;
                        try {
                            HttpUrl url = new HttpUrl(link);
                            addUnseenLink(url, base);
                        } catch (MalformedURLException mue) {
                            // FIXME: We should also do SOMETHING with javascript links, maybe just show them
                            // and provide a link to where they came from?
                            _logger.warning("Malformed link: '" + link + "'");
                        }
                    } else if (node instanceof CompositeTag) {
                        CompositeTag ctag = (CompositeTag) node;
                        recurseHtmlNodes(ctag.getChildren(), base);
                    } else if (node instanceof Tag) { // this is horrendous! Why is this not a FrameTag?!
                        Tag tag = (Tag) node;
                        if (tag.getTagName().equals("FRAME")) {
                            String src = tag.getAttribute("src");
                            if (src.startsWith("http://") || src.startsWith("https://")) {
                                try {
                                    HttpUrl url = new HttpUrl(src);
                                    addUnseenLink(url, base);
                                } catch (MalformedURLException mue) {
                                    _logger.warning("Malformed Frame src : " + src);
                                }
                            } else if (!src.startsWith("about:")) {
                                _logger.fine("Creating a new relative URL with " + base + " and " + src + " '");
                                try {
                                    HttpUrl url = new HttpUrl(base, src);
                                    addUnseenLink(url, base);
                                } catch (MalformedURLException mue) {
                                    _logger.warning("Bad relative URL (" + base.toString() + ") : " + src);
                                }
                            }
                        }
                    }
                }
            } catch (ParserException pe) {
                _logger.warning("ParserException : " + pe);
            }
        }
        
        private void addUnseenLink(HttpUrl url, HttpUrl referer) {
            if (url == null) {
                return;
            }
            if (_model.getConversationCount(url) == 0) {
                String first = _model.getUrlProperty(url, "REFERER");
                if (first == null || first.equals("")) {
                    _model.setUrlProperty(url, "REFERER", referer.toString());
                }
            }
        }
        
    }
}
