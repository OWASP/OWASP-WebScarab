/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.ui;

import org.owasp.webscarab.model.*;

import org.owasp.webscarab.plugin.WebScarabPlugin;
import org.owasp.webscarab.plugin.Plug;

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
import java.io.File;
import java.io.FileNotFoundException;

/**
 *
 * @author  rdawes
 */
public class Framework implements Plug
{

    private Logger _logger = Logger.getLogger("WebScarab");
    
    private SiteModel _sitemodel;
    
    private Parser _parser;
    
    ArrayList _plugins = null;
    WebScarabPlugin[] _pluginArray = new WebScarabPlugin[0];
    
    private String _sessionDir = null;
    
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
        _pluginArray = (WebScarabPlugin[]) _plugins.toArray(_pluginArray);
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
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].analyse(request, response, conversation, urlinfo, parsed);
        }
        
        // add the conversation to the model
        String id = _sitemodel.addConversation(conversation);
        
        // Save the Request, Response (and Conversation) here
        
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
    
    /** called to create any directory structures required by this plugin.
     * @param dir a String representing the base directory under which this session's 
     * data will be saved
     */    
    public void initDirectory(String dir) throws FileNotFoundException {
        _sessionDir = null;
        File f = new File(dir);
        if (!f.exists() && !f.mkdirs()) {
            throw new FileNotFoundException("Could not create the directory : '" + dir + "'");
        }
        // should I delete my own files that I find in this directory ??
        // Call the equivalent method for each plugin
        for (int i=0; i< _pluginArray.length; i++) {
            _pluginArray[i].initDirectory(dir);
        }
        // set sessionDir to a non-null value to indicate success in initialisation
        _sessionDir = dir;
    }
    
    /** Instructs the plugin to discard any session specific data that it may hold */
    public void discardSessionData() {
        for (int i=0; i< _pluginArray.length; i++) {
            _pluginArray[i].discardSessionData();
        }
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void saveSessionData(String dir) throws FileNotFoundException {
        // I'll save the URLInfo here. Conversations should be saved dynamically
        // since they do not change once created.
        for (int i=0; i< _pluginArray.length; i++) {
            _pluginArray[i].saveSessionData(dir);
        }
    }
    
    /** called to instruct the plugin to read any saved state data from the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */
    public void loadSessionData(String dir) throws FileNotFoundException {
        // I'll read in the list of Conversations here, as well as the URLInfo's
        for (int i=0; i< _pluginArray.length; i++) {
            _pluginArray[i].loadSessionData(dir);
        }
    }

}
