/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.ui;

import org.owasp.webscarab.model.*;

import org.owasp.webscarab.plugin.WebScarabPlugin;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.httpclient.URLFetcher;

import java.util.ArrayList;
import java.util.Properties;

import java.lang.Thread;
import java.util.logging.Logger;

import org.htmlparser.Parser;
import org.htmlparser.NodeReader;
import org.htmlparser.Node;
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
    
    private Logger _logger = Logger.getLogger("WebScarab");
    
    private SiteModel _sitemodel;
    
    private Parser _parser;
    
    private ArrayList _plugins = null;
    
    private Properties _props = null;
    
    /** Creates a new instance of WebScarab */
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
        if (_props != null) {
            plugin.setProperties(_props);
        }
    }
    
    public void setProperties(Properties props) {
        _props = props;
        setProxies(props);
        // Call the equivalent method for each plugin
        if (_plugins == null) return;
        for (int i=0; i< _plugins.size(); i++) {
            ((WebScarabPlugin)_plugins.get(i)).setProperties(props);
        }
    }
    
    public String addConversation(Request request, Response response) {
        // get a summary of the URL so far.
        URLInfo urlinfo = _sitemodel.getURLInfo(request.getURL().toString());
        // create a new conversation for the Request and Response
        Conversation conversation = new Conversation(request, response);
        // update the summary
        updateURLInfo(conversation, urlinfo);
        
        Object parsed = null;
        // parse the response, if it was HTML
        String ct = response.getHeader("Content-Type");
        if (ct != null && ct.matches("text/html.*")) {
            byte[] content = response.getContent();
            String url = request.getURL().toString();
            
            if (content != null && content.length > 0) {
                NodeReader reader = new NodeReader(new InputStreamReader(new ByteArrayInputStream(content)), url);
                NodeList nodelist = new NodeList();
                synchronized (_parser) {
                    _parser.setReader(reader);
                    try {
                        for (NodeIterator ni = _parser.elements(); ni.hasMoreNodes();) {
                            nodelist.add(ni.nextNode());
                        }
                    } catch (ParserException pe) {
                        _logger.severe("ParserException : " + pe);
                    }
                }
                parsed = nodelist;
            }
        }
        
        // call the plugins
        for (int i=0; i< _plugins.size(); i++) {
            ((WebScarabPlugin)_plugins.get(i)).analyse(request, response, conversation, urlinfo, parsed);
        }
        
        // add the conversation to the model
        String id = _sitemodel.addConversation(conversation, request, response);
        
        // return the conversation ID
        return id;
    }
    
    private void updateURLInfo(Conversation conversation, URLInfo urlinfo) {
        synchronized (urlinfo) {
            String property = "METHOD";
            String value = conversation.getProperty(property);
            if (value != null) urlinfo.setProperty(property, value); // should add it, so as not to override previous
            
            property = "STATUS";
            value = conversation.getProperty(property);
            if (value != null) urlinfo.setProperty(property, value); // should add it, so as not to override previous
            
            property = "CHECKSUM";
            value = conversation.getProperty(property);
            if (value != null) urlinfo.setProperty(property, value); // should add it, so as not to override previous
            
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
                System.out.println("NumberFormat Exception : " + nfe);
            }
            urlinfo.setProperty("TOTALBYTES", Integer.toString(urlbytes+conversationbytes));
            
            // should add it, so as not to override previous. This should not really be a Boolean,
            // rather a list of the cookies, it is difficult to concatenate a list of Set-Cookies, though :-(
            urlinfo.setProperty("SET-COOKIE", Boolean.toString(conversation.getProperty("SET-COOKIE")!=null));
        }
    }
    
    public void setProxies(Properties props) {
        String prop = "WebScarab.httpProxy";
        String value = props.getProperty(prop);
        if (value != null) {
            String[] proxy = value.split(":");
            if (proxy.length == 2) {
                try {
                    URLFetcher.setHttpProxy(proxy[0], Integer.parseInt(proxy[1]));
                } catch (NumberFormatException nfe) {
                    System.out.println("Error parsing " + prop + " from properties");
                }
            } else {
                URLFetcher.setHttpProxy(null,0);
            }
        } else {
            URLFetcher.setHttpProxy(null,0);
        }
        prop = "WebScarab.httpsProxy";
        value = props.getProperty(prop);
        if (value != null) {
            String[] proxy = value.split(":");
            if (proxy.length == 2) {
                try {
                    URLFetcher.setHttpsProxy(proxy[0], Integer.parseInt(proxy[1]));
                } catch (NumberFormatException nfe) {
                    System.out.println("Error parsing " + prop + " from properties");
                }
            } else {
                URLFetcher.setHttpsProxy(null,0);
            }
        } else {
            URLFetcher.setHttpsProxy(null,0);
        }
        prop = "WebScarab.noProxy";
        value = props.getProperty(prop);
        if (value != null) {
            URLFetcher.setNoProxy(value.split(", *"));
        } else {
            URLFetcher.setNoProxy(new String[0]);
        }
    }
    
    public void setSessionStore(Object store) throws StoreException {
        _sitemodel.setSessionStore(store);
        // Call the equivalent method for each plugin
        for (int i=0; i< _plugins.size(); i++) {
            ((WebScarabPlugin)_plugins.get(i)).setSessionStore(store);
        }
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */
    public void saveSessionData() throws StoreException {
        _sitemodel.saveSessionData();
        for (int i=0; i< _plugins.size(); i++) {
            ((WebScarabPlugin)_plugins.get(i)).saveSessionData();
        }
    }
    
}
