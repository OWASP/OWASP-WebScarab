/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * Framework.java
 *
 * Created on June 16, 2004, 8:57 AM
 */

package org.owasp.webscarab.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.LinkedList;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.jar.Attributes.Name;
import java.util.logging.Logger;
import java.util.Vector;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.owasp.webscarab.httpclient.HTTPClientFactory;
import org.owasp.webscarab.httpclient.SSLContextManager;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.StoreException;

/**
 * creates a class that contains and controls the plugins.
 * @author knoppix
 */
public class Framework {
    
    private List _plugins = new ArrayList();
    private List _analysisQueue = new LinkedList();
    
    private FrameworkModel _model;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _version;
    
    private FrameworkUI _ui = null;
    
    private ScriptManager _scriptManager;
    private CredentialManager _credentialManager;
    
    private AddConversationHook _allowAddConversation;
    
    private Hook _analyseConversation;
    
    private Thread _queueThread = null;
    private QueueProcessor _qp = null;
    
    private Pattern dropPattern = null;
    
    /**
     * Creates a new instance of Framework
     */
    public Framework() {
        _model = new FrameworkModel();
        _scriptManager = new ScriptManager(this);
        _allowAddConversation = new AddConversationHook();
        _scriptManager.registerHooks("Framework", new Hook[] { _allowAddConversation });
        extractVersionFromManifest();
        _credentialManager = new CredentialManager();
        configureHTTPClient();
        String dropRegex = Preferences.getPreference("WebScarab.dropRegex", null);
        if (dropRegex != null) {
            try {
                dropPattern = Pattern.compile(dropRegex);
            } catch (PatternSyntaxException pse) {
                _logger.warning("Got an invalid regular expression for conversations to ignore: " + dropRegex + " results in " + pse.toString());
            }
        }
        _qp = new Framework.QueueProcessor();
        _queueThread = new Thread(_qp, "QueueProcessor");
        _queueThread.setDaemon(true);
        _queueThread.setPriority(Thread.MIN_PRIORITY);
        _queueThread.start();
    }
    
    public ScriptManager getScriptManager() {
        return _scriptManager;
    }
    
    public CredentialManager getCredentialManager() {
        return _credentialManager;
    }
    
    /**
     * links the framework to its GUI
     * @param ui a class implementing the necessary interface methods
     */
    public void setUI(FrameworkUI ui) {
        _ui = ui;
    }
    
    /**
     * instructs the framework to use the provided model. The framework notifies all
     * plugins that the session has changed.
     */
    public void setSession(String type, Object store, String session) throws StoreException {
        _model.setSession(type, store, session);
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (!plugin.isRunning()) {
                plugin.setSession(type, store, session);
            } else {
                _logger.warning(plugin.getPluginName() + " is running while we are setting the session");
            }
        }
    }
    
    /**
     * provided to allow plugins to gain access to the model.
     * @return the SiteModel
     */
    public FrameworkModel getModel() {
        return _model;
    }
    
    private void extractVersionFromManifest() {
        Package pkg = Package.getPackage("org.owasp.webscarab");
        if (pkg != null) _version = pkg.getImplementationVersion();
        else _logger.severe("PKG is null");
        if (_version == null) _version = "unknown (local build?)";
    }
    
    /**
     * adds a new plugin into the framework
     * @param plugin the plugin to add
     */
    public void addPlugin(Plugin plugin) {
        _plugins.add(plugin);
        Hook[] hooks = plugin.getScriptingHooks();
        _scriptManager.registerHooks(plugin.getPluginName(), hooks);
    }
    
    /** 
     * retrieves the named plugin, if it exists
     * @param name the name of the plugin
     * @return the plugin if it exists, or null
     */
    public Plugin getPlugin(String name) {
        Plugin plugin = null;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            plugin = (Plugin) it.next();
            if (plugin.getPluginName().equals(name)) return plugin;
        }
        return null;
    }
    
    /**
     * starts all the plugins in the framework
     */
    public void startPlugins() {
        HTTPClientFactory.getInstance().getSSLContextManager().invalidateSessions();
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (!plugin.isRunning()) {
                Thread t = new Thread(plugin, plugin.getPluginName());
                t.setDaemon(true);
                t.start();
            } else {
                _logger.warning(plugin.getPluginName() + " was already running");
            }
        }
        _scriptManager.loadScripts();
    }
    
    public boolean isBusy() {
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isBusy()) return true;
        }
        return false;
    }
    
    public boolean isRunning() {
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isRunning()) return true;
        }
        return false;
    }
    
    public boolean isModified() {
        if (_model.isModified()) return true;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isModified()) return true;
        }
        return false;
    }
    
    public String[] getStatus() {
        List status = new ArrayList();
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            status.add(plugin.getPluginName() + " : " + plugin.getStatus());
        }
        return (String[]) status.toArray(new String[0]);
    }
    
    /**
     * stops all the plugins in the framework
     */
    public boolean stopPlugins() {
        if (isBusy()) return false;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isRunning()) {
                // _logger.info("Stopping " + plugin.getPluginName());
                plugin.stop();
                // _logger.info("Done");
            } else {
                _logger.warning(plugin.getPluginName() + " was not running");
            }
        }
        _scriptManager.saveScripts();
        return true;
    }
    
    /**
     * called to instruct the various plugins to save their current state to the store.
     * @throws StoreException if there is any problem saving the session data
     */
    public void saveSessionData() throws StoreException {
        StoreException storeException = null;
        if (_model.isModified()) {
            _logger.info("Flushing model");
            _model.flush();
            _logger.info("Done");
        }
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isModified()) {
                try {
                    _logger.info("Flushing " + plugin.getPluginName());
                    plugin.flush();
                    _logger.info("Done");
                } catch (StoreException se) {
                    if (storeException == null) storeException = se;
                    _logger.severe("Error saving data for " + plugin.getPluginName() + ": " + se);
                }
            }
        }
        
        if (storeException != null) throw storeException;
    }
    
    /**
     * returns the build version of WebScarab. This is extracted from the webscarab.jar
     * Manifest, if webscarab is running from a jar.
     * @return the version string
     */
    public String getVersion() {
        return _version;
    }
    
    public ConversationID reserveConversationID() {
        return _model.reserveConversationID();
    }
    
    public void addConversation(ConversationID id, Request request, Response response, String origin) {
        addConversation(id, new Date(), request, response, origin);
    }
    
    public void addConversation(ConversationID id, Date when, Request request, Response response, String origin) {
        ScriptableConversation conversation = new ScriptableConversation(request, response, origin);
        _allowAddConversation.runScripts(conversation);
        if (conversation.isCancelled()) return;
        if (dropPattern != null && dropPattern.matcher(request.getURL().toString()).matches()) {
            return;
        }
        _model.addConversation(id, when, request, response, origin);
        if (!conversation.shouldAnalyse()) return;
        synchronized(_analysisQueue) {
            _analysisQueue.add(id);
        }
    }
    
    public ConversationID addConversation(Request request, Response response, String origin) {
        ConversationID id = reserveConversationID();
        addConversation(id, new Date(), request, response, origin);
        return id;
    }
    
    private void configureHTTPClient() {
        HTTPClientFactory factory = HTTPClientFactory.getInstance();
        String prop = null;
        String value;
        int colon;
        try {
            // FIXME for some reason, we get "" instead of null for value,
            // and do not use our default value???
            prop = "WebScarab.httpProxy";
            value = Preferences.getPreference(prop);
            if (value == null || value.equals("")) value = ":3128";
            colon = value.indexOf(":");
            factory.setHttpProxy(value.substring(0,colon), Integer.parseInt(value.substring(colon+1).trim()));
            
            prop = "WebScarab.httpsProxy";
            value = Preferences.getPreference(prop);
            if (value == null || value.equals("")) value = ":3128";
            colon = value.indexOf(":");
            factory.setHttpsProxy(value.substring(0,colon), Integer.parseInt(value.substring(colon+1).trim()));
            
            prop = "WebScarab.noProxy";
            value = Preferences.getPreference(prop, "");
            if (value == null) value = "";
            factory.setNoProxy(value.split(" *, *"));
            
            int connectTimeout = 30000;
            prop = "HttpClient.connectTimeout";
            value = Preferences.getPreference(prop,"");
            if (value != null && !value.equals("")) {
                try {
                    connectTimeout = Integer.parseInt(value);
                } catch (NumberFormatException nfe) {}
            }
            int readTimeout = 0;
            prop = "HttpClient.readTimeout";
            value = Preferences.getPreference(prop,"");
            if (value != null && !value.equals("")) {
                try {
                    readTimeout = Integer.parseInt(value);
                } catch (NumberFormatException nfe) {}
            }
            factory.setTimeouts(connectTimeout, readTimeout);
            
        } catch (NumberFormatException nfe) {
            _logger.warning("Error parsing property " + prop + ": " + nfe);
        } catch (Exception e) {
            _logger.warning("Error configuring the HTTPClient property " + prop + ": " + e);
        }
        factory.setAuthenticator(_credentialManager);
    }
    
    private class QueueProcessor implements Runnable {
        
        public void run() {
            while (true) {
                ConversationID id = null;
                synchronized (_analysisQueue) {
                    if (_analysisQueue.size()>0)
                        id = (ConversationID) _analysisQueue.remove(0);
                }
                if (id != null) {
                    Request request = _model.getRequest(id);
                    Response response = _model.getResponse(id);
                    String origin = _model.getConversationOrigin(id);
                    Iterator it = _plugins.iterator();
                    while (it.hasNext()) {
                        Plugin plugin = (Plugin) it.next();
                        if (plugin.isRunning()) {
                            try {
                                plugin.analyse(id, request, response, origin);
                            } catch (Exception e) {
                                _logger.warning(plugin.getPluginName() + " failed to process " + id + ": " + e);
                                e.printStackTrace();
                            }
                        }
                    }
                } else {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException ie) {}
                }
            }
        }
        
    }
    
    private class AddConversationHook extends Hook {
        
        public AddConversationHook() {
            super("Add Conversation", 
            "Called when a new conversation is added to the framework.\n" +
            "Use conversation.setCancelled(boolean) and conversation.setAnalyse(boolean) " +
            "after deciding using conversation.getRequest() and conversation.getResponse()");
        }
        
        public void runScripts(ScriptableConversation conversation) {
            if (_bsfManager == null) return;
            synchronized(_bsfManager) {
                try {
                    _bsfManager.declareBean("conversation", conversation, conversation.getClass());
                    super.runScripts();
                    _bsfManager.undeclareBean("connection");
                } catch (Exception e) {
                    _logger.severe("Declaring or undeclaring a bean should not throw an exception! " + e);
                }
            }
        }
        
    }
    
}
