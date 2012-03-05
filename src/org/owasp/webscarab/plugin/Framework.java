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

import EDU.oswego.cs.dl.util.concurrent.QueuedExecutor;
import EDU.oswego.cs.dl.util.concurrent.ThreadFactory;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.owasp.webscarab.httpclient.HTTPClientFactory;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.fragments.Fragments;

/**
 * creates a class that contains and controls the plugins.
 * @author knoppix
 */
public class Framework {
    
    private ArrayList<Plugin> _plugins = new ArrayList<Plugin>();
    private final QueuedExecutor analysisQueuedExecutor;
    private final QueuedExecutor analysisLongRunningQueuedExecutor;
    
    private FrameworkModel _model;
    private FrameworkModelWrapper _wrapper;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _version;
    
    private ScriptManager _scriptManager;
    private CredentialManager _credentialManager;
    
    private AddConversationHook _allowAddConversation;
    
    private AnalyseConversationHook _analyseConversation;
    
    private Pattern dropPattern = null;
    private Pattern whitelistPattern = null;
    
    /**
     * Creates a new instance of Framework
     */
    public Framework() {
        _model = new FrameworkModel();
        _wrapper = new FrameworkModelWrapper(_model);
        _scriptManager = new ScriptManager(this);
        _allowAddConversation = new AddConversationHook();
        _analyseConversation = new AnalyseConversationHook();
        _scriptManager.registerHooks("Framework", new Hook[] { _allowAddConversation, _analyseConversation });
        extractVersionFromManifest();
        _credentialManager = new CredentialManager();
        configureHTTPClient();
        String dropRegex = Preferences.getPreference("WebScarab.dropRegex", null);
        try {
            setDropPattern(dropRegex);
        } catch (PatternSyntaxException pse) {
            _logger.warning("Got an invalid regular expression for conversations to ignore: " + dropRegex + " results in " + pse.toString());
        }
        String whitelistRegex = Preferences.getPreference("WebScarab.whitelistRegex", null);
        try {
        	setWhitelistPattern(whitelistRegex);
        } catch (PatternSyntaxException pse) {
        	_logger.warning("Got an invalid regular expression for conversations to whitelist: " + whitelistRegex + " results in " + pse.toString());
        }
        this.analysisQueuedExecutor = new QueuedExecutor();
        this.analysisQueuedExecutor.setThreadFactory(new QueueProcessorThreadFactory("QueueProcessor"));
        this.analysisLongRunningQueuedExecutor = new QueuedExecutor();
        this.analysisLongRunningQueuedExecutor.setThreadFactory(new QueueProcessorThreadFactory("Long Running QueueProcessor"));
    }
    
    private static final class QueueProcessorThreadFactory implements ThreadFactory {

        private final String threadName;
        
        public QueueProcessorThreadFactory(String threadName) {
            this.threadName = threadName;
        }
        
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r);
            thread.setName(this.threadName);
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        }
    }
    
    public ScriptManager getScriptManager() {
        return _scriptManager;
    }
    
    public CredentialManager getCredentialManager() {
        return _credentialManager;
    }
    
    public String getDropPattern() {
        return dropPattern == null ? "" : dropPattern.pattern();
    }
    public void setWhitelistPattern(String pattern) throws PatternSyntaxException{
    	if (pattern == null || "".equals(pattern)) {
    		whitelistPattern = null;
    		Preferences.setPreference("WebScarab.whitelistRegex", "");
    	} else {
    		whitelistPattern = Pattern.compile(pattern);
    		Preferences.setPreference("WebScarab.whitelistRegex", pattern);
    	}
    	System.out.println("Using WebScarab.whitelistRegex pattern : "+pattern+". Will not save any data for requests not matching this pattern");
    }
    public void setDropPattern(String pattern) throws PatternSyntaxException {
        if (pattern == null || "".equals(pattern)) {
            dropPattern = null;
            Preferences.setPreference("WebScarab.dropRegex", "");
        } else {
            dropPattern = Pattern.compile(pattern);
            Preferences.setPreference("WebScarab.dropRegex", pattern);
        }
    }
    
    /**
     * instructs the framework to use the provided model. The framework notifies all
     * plugins that the session has changed.
     */
    public void setSession(String type, Object store, String session) throws StoreException {
        _model.setSession(type, store, session);
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
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
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            plugin = it.next();
            if (plugin.getPluginName().equals(name)) return plugin;
        }
        return null;
    }
    
    /**
     * starts all the plugins in the framework
     */
    public void startPlugins() {
        HTTPClientFactory.getInstance().getSSLContextManager().invalidateSessions();
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
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
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
            if (plugin.isBusy()) return true;
        }
        return false;
    }
    
    public boolean isRunning() {
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
            if (plugin.isRunning()) return true;
        }
        return false;
    }
    
    public boolean isModified() {
        if (_model.isModified()) return true;
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
            if (plugin.isModified()) return true;
        }
        return false;
    }
    
    public String[] getStatus() {
        List<String> status = new ArrayList<String>();
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
            status.add(plugin.getPluginName() + " : " + plugin.getStatus());
        }
        return status.toArray(new String[0]);
    }
    
    /**
     * stops all the plugins in the framework
     */
    public boolean stopPlugins() {
        if (isBusy()) return false;
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
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
        Iterator<Plugin> it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = it.next();
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
        ScriptableConversation conversation = new ScriptableConversation(id, request, response, origin);
        _allowAddConversation.runScripts(conversation);
        if (conversation.isCancelled()) return;
        //Do we have whitelisting? If so, check if it matches
        if(whitelistPattern != null && !whitelistPattern.matcher(request.getURL().toString()).matches())
        {
        	return;
        }
        // Also, check blacklist - drop pattern
        
        if (dropPattern != null && dropPattern.matcher(request.getURL().toString()).matches()) {
            return;
        }
        _model.addConversation(id, when, request, response, origin);
        if (!conversation.shouldAnalyse()) return;
        _analyseConversation.runScripts(conversation);
        try {
            this.analysisQueuedExecutor.execute(new QueueProcessor(id));
            this.analysisLongRunningQueuedExecutor.execute(new QueueProcessor(id, true));
        } catch (InterruptedException ex) {
            _logger.severe("error scheduling analysis task: " + ex.getMessage());
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
        
        private final ConversationID id;
        
        private final boolean longRunning;
        
        public QueueProcessor(ConversationID id) {
            this(id, false);
        }
        
        public QueueProcessor(ConversationID id, boolean longRunning) {
            this.id = id;
            this.longRunning = longRunning;
        }
        
        public void run() {
            if (null == this.id) {
                return;
            }
            Request request = _model.getRequest(id);
            Response response = _model.getResponse(id);
            String origin = _model.getConversationOrigin(id);
            Iterator<Plugin> it = _plugins.iterator();
            while (it.hasNext()) {
                Plugin plugin = it.next();
                if (this.longRunning) {
                    if (false == plugin instanceof Fragments) {
                        continue;
                    }
                    _logger.info("running long running analysis: " + plugin.getPluginName());
                } else {
                    if (plugin instanceof Fragments) {
                        continue;
                    }
                }
                if (plugin.isRunning()) {
                    try {
                        long t0 = System.currentTimeMillis();
                        plugin.analyse(id, request, response, origin);
                        long t1 = System.currentTimeMillis();
                        long dt = t1 - t0;
                        if (dt > 1000 * 10) {
                            _logger.warning("plugin " + plugin.getPluginName() + " is taking a long time to analyse conversation " + id + " (" + dt + " milliseconds)");
                        }
                    } catch (Exception e) {
                        _logger.warning(plugin.getPluginName() + " failed to process " + id + ": " + e);
                        e.printStackTrace();
                    }
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
                    _bsfManager.undeclareBean("conversation");
                } catch (Exception e) {
                    _logger.severe("Declaring or undeclaring a bean should not throw an exception! " + e);
                }
            }
        }
        
    }

    private class AnalyseConversationHook extends Hook {
    	
        public AnalyseConversationHook() {
            super("Analyse Conversation", 
            "Called when a new conversation is added to the framework.\n" +
            "Use model.setConversationProperty(id, property, value) to assign properties");
        }
        
        public void runScripts(ScriptableConversation conversation) {
            if (_bsfManager == null) return;
            synchronized(_bsfManager) {
                try {
                    _bsfManager.declareBean("id", conversation.getId(), conversation.getId().getClass());
                    _bsfManager.declareBean("conversation", conversation, conversation.getClass());
                    _bsfManager.declareBean("model", _wrapper, _wrapper.getClass());
                    super.runScripts();
                    _bsfManager.undeclareBean("conversation");
                } catch (Exception e) {
                    _logger.severe("Declaring or undeclaring a bean should not throw an exception! " + e);
                }
            }
        }
    }
}
