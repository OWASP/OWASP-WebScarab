/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.ui;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.CookieJar;
import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.URLInfo;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.httpclient.URLFetcher;

import org.owasp.webscarab.plugin.WebScarabPlugin;
import org.owasp.webscarab.plugin.Plug;

import java.util.ArrayList;
import java.util.Properties;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.util.logging.Logger;

import org.htmlparser.Parser;
import org.htmlparser.NodeReader;
import org.htmlparser.Node;
import org.htmlparser.RemarkNode;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileNotFoundException;

/**
 *
 * @author  rdawes
 */
public class Framework implements Plug {
    
    private SiteModel _sitemodel;
    
    private Parser _parser;
    
    private ArrayList _plugins = null;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    // private Pattern _errorPattern = Pattern.compile("ODBC|stack trace|Error report", Pattern.DOTALL | Pattern.MULTILINE);
    
    /** Creates a new instance of Framework */
    public Framework() {
        _sitemodel = new SiteModel();
        
        _parser = new Parser();
        _parser.registerScanners();
    }
    
    public SiteModel getSiteModel() {
        return _sitemodel;
    }
    
    public void addPlugin(WebScarabPlugin plugin) {
        if (_plugins == null) {
            _plugins = new ArrayList();
        }
        _plugins.add(plugin);
    }
    
    public String addConversation(String source, Request request, Response response) {
        // get a summary of the URL so far.
        URLInfo urlinfo = _sitemodel.getURLInfo(request.getURL());
        // create a new conversation for the Request and Response
        Conversation conversation = new Conversation(request, response);
        conversation.setProperty("ORIGIN", source);
        
        // update the summary
        updateURLInfo(conversation, urlinfo);
        
        Object parsed = null;
        // parse the response, if it was HTML
        String ct = response.getHeader("Content-Type");
        if (ct != null && ct.matches("text/html.*")) {
            parsed = parseHTML(request.getURL().toString(), response.getContent());
        }
        
        // perform local analysis
        analyse(request, response, conversation, urlinfo, parsed);
        
        // call the plugins analysis routines
        for (int i=0; i< _plugins.size(); i++) {
            ((WebScarabPlugin)_plugins.get(i)).analyse(request, response, conversation, urlinfo, parsed);
        }
        
        // add the conversation to the model
        String id = _sitemodel.addConversation(conversation, request, response);
        
        // return the conversation ID
        return id;
    }
    
    private Object parseHTML(String url, byte[] content) {
        if (content != null && content.length > 0) {
            NodeReader reader = new NodeReader(new InputStreamReader(new ByteArrayInputStream(content)), url);
            NodeList nodelist = new NodeList();
            synchronized (_parser) {
                _parser.setReader(reader);
                try {
                    Node n;
                    for (NodeIterator ni = _parser.elements(); ni.hasMoreNodes();) {
                        n = ni.nextNode();
                        nodelist.add(n);
                    }
                } catch (ParserException pe) {
                    _logger.severe("ParserException : " + pe);
                }
            }
            return nodelist;
        }
        return null;
    }
    
    private void analyse(Request request, Response response, Conversation conversation, URLInfo urlinfo, Object parsed) {
        if (parsed instanceof NodeList) {
            NodeList nodelist = (NodeList) parsed;
            try {
                NodeList comments = nodelist.searchFor(RemarkNode.class);
                NodeList scripts = nodelist.searchFor(ScriptTag.class);
                for (NodeIterator ni = comments.elements(); ni.hasMoreNodes();) {
                    String key = _sitemodel.addFragment(ni.nextNode().toHtml());
                    conversation.addProperty("COMMENTS",key);
                    urlinfo.addProperty("COMMENTS", key);
                }
                for (NodeIterator ni = scripts.elements(); ni.hasMoreNodes();) {
                    String key = _sitemodel.addFragment(ni.nextNode().toHtml());
                    conversation.addProperty("SCRIPTS",key);
                    urlinfo.addProperty("SCRIPTS", key);
                }
            } catch (ParserException pe) {
                _logger.severe("Parser exception " + pe);
            }
            /* FIXME
             * Commented until we can test this properly, and work out what we want to check for
            String content = new String(response.getContent());
            Matcher matcher = _errorPattern.matcher(content);
            if (matcher.matches()) {
                conversation.setProperty("ERRORS", "TRUE");
                urlinfo.setProperty("ERRORS", "TRUE");
            }
             */
        }
    }
    
    private void updateURLInfo(Conversation conversation, URLInfo urlinfo) {
        if (conversation == null) {
            _logger.severe("Conversation may not be null!");
            return;
        }
        if (urlinfo == null) {
            _logger.severe("urlinfo may not be null!");
            return;
        }
        synchronized (urlinfo) {
            String property = "METHOD";
            String value = conversation.getProperty(property);
            if (value != null) urlinfo.addProperty(property, value);
            
            property = "STATUS";
            value = conversation.getProperty(property);
            if (value != null) urlinfo.addProperty(property, value);
            
            property = "CHECKSUM";
            value = conversation.getProperty(property);
            if (value != null) urlinfo.addProperty(property, value);
            
            int conversationbytes = 0;
            int urlbytes = 0;
            try {
                String total = urlinfo.getProperty("TOTALBYTES");
                if (total != null) {
                    urlbytes = Integer.parseInt(total);
                }
                String size = conversation.getProperty("SIZE");
                if (size != null) {
                    conversationbytes = Integer.parseInt(size);
                }
            } catch (NumberFormatException nfe) {
                _logger.severe("NumberFormat Exception : " + nfe);
            }
            urlinfo.setProperty("TOTALBYTES", Integer.toString(urlbytes+conversationbytes));
            
            // This should not really be a Boolean, rather a list of the cookies,
            // it is difficult to concatenate a list of Set-Cookies, though :-(
            urlinfo.setProperty("SET-COOKIE", Boolean.toString(conversation.getProperty("SET-COOKIE")!=null));
        }
    }
    
    public void setSessionStore(Object store) throws StoreException {
        _sitemodel.setSessionStore(store);
        // Call the equivalent method for each plugin
        if (_plugins == null || _plugins.size() == 0) return;
        for (int i=0; i< _plugins.size(); i++) {
            WebScarabPlugin wsp = (WebScarabPlugin)_plugins.get(i);
            if (wsp != null)  {
                wsp.setSessionStore(store);
            }
        }
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */
    public void saveSessionData() throws StoreException {
        _sitemodel.saveSessionData();
        if (_plugins == null || _plugins.size() == 0) return;
        for (int i=0; i< _plugins.size(); i++) {
            WebScarabPlugin wsp = (WebScarabPlugin)_plugins.get(i);
            if (wsp != null)  {
                wsp.saveSessionData();
            }
        }
    }
    
    public CookieJar getCookieJar() {
        return _sitemodel.getCookieJar();
    }
    
    
}
