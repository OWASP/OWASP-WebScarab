/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.*;

import org.owasp.webscarab.plugin.*;
import org.owasp.webscarab.plugin.proxy.*;
import org.owasp.webscarab.plugin.proxy.module.*;

import java.util.ArrayList;
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

/**
 *
 * @author  rdawes
 */
public class WebScarab
	implements Plug
{

    private Logger _logger = Logger.getLogger("WebScarab");
    
    private SiteModel _sitemodel;
    private Proxy _proxy;
    // private Spider _spider;
    
    private Parser _parser;
    
    ArrayList _plugins = null;
    WebScarabPlugin[] _pluginArray = new WebScarabPlugin[0];
    
    /** Creates a new instance of WebScarab */
    public WebScarab() {
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
        _pluginArray = (WebScarabPlugin[]) _plugins.toArray(_pluginArray);
    }

    public String addConversation(Conversation conversation) {
        // add the conversation to the model
        String id = _sitemodel.addConversation(conversation);
        // get a summary of the URL so far.
        URLInfo urlinfo = _sitemodel.createURLInfo(conversation);
        
        String ct = conversation.getResponse().getHeader("Content-Type");
        if (ct != null && ct.matches("text/html.*")) {
            byte[] content = conversation.getResponse().getContent();
            String url = conversation.getRequest().getURL().toString();
        
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
                conversation.setNodeList(nodelist);
            }
        }
        
        // call the plugins
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].analyse(conversation, urlinfo);
        }
        
        // now write what we know about the conversation to disk
        
        // Then clean up the interim data objects in the Conversation to save memory
        // kills the Request, Response and NodeList
        conversation.flush();
        
        return id;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        WebScarab ws = new WebScarab();
        
        Proxy proxy = new Proxy(ws);
        proxy.addPlugin(new ManualEdit());
        proxy.addPlugin(new RevealHidden());
        new Thread(proxy).start();
        
        ws.addPlugin(proxy);

        // we could also add the spider, etc here.
        
    }
    
}
