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

/**
 *
 * @author  rdawes
 */
public class WebScarab
	implements Plug
{
    
    private SiteModel _sitemodel;
    private Proxy _proxy;
    // private Spider _spider;

    ArrayList _plugins = null;
    WebScarabPlugin[] _pluginArray = new WebScarabPlugin[0];
    
    /** Creates a new instance of WebScarab */
    public WebScarab() {
        _sitemodel = new SiteModel();
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
        URLInfo urlinfo = _sitemodel.getURLInfo(conversation);
        
        String ct = conversation.getResponse().getHeader("Content-Type");
        if (ct != null && ct.startsWith("text/html")) {
            // HTMLParser hp = new HTMLParser()
            // hp.parse(conversation);
        }
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].analyse(conversation, urlinfo);
        }
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
