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
 * $Id: Proxy.java,v 1.24 2005/05/18 15:23:31 rogan Exp $
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;

import java.lang.NumberFormatException;
import java.util.Vector;
import java.util.ArrayList;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.logging.Logger;

import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Script;
import org.owasp.webscarab.plugin.ScriptManager;

import java.net.MalformedURLException;
import java.net.InetAddress;

/**
 * The Proxy plugin supports multiple Listeners, and starts and stops them as
 * instructed. All requests and responses are submitted to the model, unless there
 * is an error while retrieving the response.
 */
public class Proxy implements Plugin {
    
    private boolean _running = false;
    
    private Framework _framework = null;
    
    private ProxyUI _ui = null;
    
    private ArrayList _plugins = new ArrayList();
    private TreeMap _listeners = new TreeMap();
    private TreeMap _simulators = new TreeMap();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _status = "Stopped";
    private int _pending = 0;
    
    private Proxy.ConnectionHook _allowConnection = new ConnectionHook(
    "Allow connection", 
    "Called when a new connection is received from a browser\n" +
    "use connection.getAddress() and connection.closeConnection() to decide and react"
    );
    
    private Proxy.ConnectionHook _interceptRequest = new ConnectionHook(
    "Intercept request", 
    "Called when a new request has been submitted by the browser\n" +
    "use connection.getRequest() and connection.setRequest(request) to perform changes"
    );
    
    private Proxy.ConnectionHook _interceptResponse = new ConnectionHook(
    "Intercept response", 
    "Called when the request has been submitted to the server, and the response " + 
    "has been recieved.\n" +
    "use connection.getResponse() and connection.setResponse(response) to perform changes"
    );
    
    /**
     * Creates a Proxy Object with a reference to the Framework. Creates (but does not
     * start) the configured Listeners.
     * @param model The Model to submit requests and responses to
     */
    public Proxy(Framework framework) {
        _framework = framework;
        createSimulators();
        createListeners();
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[] { _allowConnection, _interceptRequest, _interceptResponse };
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    /**
     * called by Listener to determine whether to allow a connection or not
     */
    void allowClientConnection(ScriptableConnection connection) {
        _allowConnection.runScripts(connection);
    }
    
    /**
     * called by Connectionhandler via Listener to perform any required
     * modifications to the Request
     */
    void interceptRequest(ScriptableConnection connection) {
        _interceptRequest.runScripts(connection);
    }
    
    /**
     * called by Connectionhandler via Listener to perform any required
     * modifications to the Response
     */
    void interceptResponse(ScriptableConnection connection) {
        _interceptResponse.runScripts(connection);
    }
    
    public void setUI(ProxyUI ui) {
        _ui = ui;
        if (_ui != null) _ui.setEnabled(_running);
    }
    
    public void addPlugin(ProxyPlugin plugin) {
        _plugins.add(plugin);
    }
    
    /** 
     * retrieves the named plugin, if it exists
     * @param name the name of the plugin
     * @return the plugin if it exists, or null
     */
    public ProxyPlugin getPlugin(String name) {
        ProxyPlugin plugin = null;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            plugin = (ProxyPlugin) it.next();
            if (plugin.getPluginName().equals(name)) return plugin;
        }
        return null;
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Proxy");
    }
    
    /**
     * returns a list of keys describing the configured Listeners
     * @return the list of keys
     */
    public String[] getProxies() {
        if (_listeners.size()==0) {
            return new String[0];
        }
        return (String[]) _listeners.keySet().toArray(new String[0]);
    }
    
    /**
     * used to obtain the address that the referenced Listener is bound to
     * @param key the key referring to a configured Listener
     * @return the address that the Listener is listening to
     */
    public String getAddress(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.getAddress();
        } else {
            return null;
        }
    }
    
    public int getPort(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.getPort();
        } else {
            return -1;
        }
    }
    
    public HttpUrl getBase(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.getBase();
        } else {
            return null;
        }
    }
    
    /**
     * Used to obtain a list of known network simulators, which can be used to simulate
     * a modem or other bandwidth limited connection
     * @return an array of Simulator keys
     */
    public String[] getSimulators() {
        return (String[])_simulators.keySet().toArray(new String[0]);
    }
    
    public String getSimulator(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            NetworkSimulator netsim = l.getSimulator();
            if (netsim != null) {
                return netsim.getName();
            } else {
                return "Unlimited";
            }
        } else {
            return "Unlimited";
        }
    }
    
    public boolean isPrimaryProxy(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.isPrimaryProxy();
        } else {
            return false;
        }
    }
    
    /**
     * called by ConnectionHandler to see which plugins have been configured.
     * @return an array of ProxyPlugin's
     */
    protected ProxyPlugin[] getPlugins() {
        ProxyPlugin[] plugins = new ProxyPlugin[_plugins.size()];
        for (int i=0; i<_plugins.size(); i++) {
            plugins[i] = (ProxyPlugin) _plugins.get(i);
        }
        return plugins;
    }
    
    /**
     * used by the User Interface to start a new proxy listening with the specified
     * parameters
     * @param address the address to listen to, null or "" implies localhost, "*" implies all
     * interfaces
     * @param port the port to listen on
     * @param base a string such as "http://site:port/" which is used by reverse proxies to
     * indicate the address that it is acting as.
     * @param simulator a String referring to a network simulator
     * @param usePlugins indicates whether the ConnectionHandlers spawned by this Listener should pass
     * Requests and Responses through the defined proxy plugins
     * @throws IOException if there are any problems starting the Listener
     */
    
    public void addListener(String address, int port, HttpUrl base, String simulator, boolean primary) throws IOException {
        Listener l = createListener(address, port, base, simulator, primary);
        startListener(l);
        
        String key = l.getKey();
        Preferences.setPreference("Proxy.listener." + key + ".base", base == null ? "" : base.toString());
        Preferences.setPreference("Proxy.listener." + key + ".simulator", simulator);
        Preferences.setPreference("Proxy.listener." + key + ".primary", primary == true ? "yes" : "no");
        
        String value = null;
        Iterator i = _listeners.keySet().iterator();
        while (i.hasNext()) {
            key = (String) i.next();
            if (value == null) {
                value = key;
            } else {
                value = value + ", " + key;
            }
        }
        Preferences.setPreference("Proxy.listeners", value);
    }
    
    private void startListener(Listener l) {
        Thread t = new Thread(l, "Listener-"+l.getKey());
        t.setDaemon(true);
        t.start();
        if (_ui != null) _ui.proxyStarted(l.getKey());
    }
    
    private boolean stopListener(Listener l) {
        boolean stopped = l.stop();
        if (stopped && _ui != null) _ui.proxyStopped(l.getKey());
        return stopped;
    }
    
    /**
     * Used to stop the referenced listener
     * @param key the Listener to stop
     * @return true if the proxy was successfully stopped, false otherwise
     */
    public boolean removeListener(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l == null) return false;
        if (stopListener(l)) {
            _listeners.remove(key);
            if (_ui != null) _ui.proxyRemoved(key);
            Preferences.remove("Proxy.listener." + key + ".base");
            Preferences.remove("Proxy.listener." + key + ".simulator");
            Preferences.remove("Proxy.listener." + key + ".primary");
            String value = null;
            Iterator i = _listeners.keySet().iterator();
            while (i.hasNext()) {
                key = (String) i.next();
                if (value == null) {
                    value = key;
                } else {
                    value = value + ", " + key;
                }
            }
            if (value == null) {
                value = "";
            }
            Preferences.setPreference("Proxy.listeners", value);
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Starts the Listeners
     */
    public void run() {
        Iterator it = _listeners.keySet().iterator();
        while (it.hasNext()) {
            String key = (String) it.next();
            Listener l = (Listener) _listeners.get(key);
            startListener(l);
        }
        _running = true;
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Started, Idle";
    }
    
    /**
     * Stops the Listeners
     * @return true if successful, false otherwise
     */
    public boolean stop() {
        _running = false;
        Iterator it = _listeners.keySet().iterator();
        while (it.hasNext()) {
            String key = (String) it.next();
            Listener l = (Listener) _listeners.get(key);
            if (!stopListener(l)) {
                _logger.severe("Failed to stop Listener-" + l.getKey());
                _running = true;
            }
        }
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
        return ! _running;
    }
    
    /**
     * used by ConnectionHandler to notify the Proxy (and any listeners) that it is
     * handling a particular request
     * @param request the request to log
     * @return the conversation ID
     */
    protected ConversationID gotRequest(Request request) {
        ConversationID id = _framework.reserveConversationID();
        if (_ui != null) _ui.requested(id, request.getMethod(), request.getURL());
        _pending++;
        _status = "Started, " + _pending + " in progress";
        return id;
    }
    
    /**
     * used by ConnectionHandler to notify the Proxy (and any listeners) that it has
     * handled a particular request and response, and that it should be logged and
     * analysed
     * @param id the Conversation ID
     * @param response the Response
     */
    protected void gotResponse(ConversationID id, Response response) {
        if (_ui != null) _ui.received(id, response.getStatusLine());
        _framework.addConversation(id, response.getRequest(), response, getPluginName());
        _pending--;
        _status = "Started, " + (_pending>0? (_pending + " in progress") : "Idle");
    }
    
    /**
     * notifies any observers that the request failed to complete, and the reason for it
     * @param reason the reason for failure
     * @param id the conversation ID
     */
    protected void failedResponse(ConversationID id, String reason) {
        if (_ui != null) _ui.aborted(id, reason);
        _pending--;
        _status = "Started, " + (_pending>0? (_pending + " in progress") : "Idle");
    }
    
    private void createSimulators() {
        _simulators.put("Unlimited", null);
        _simulators.put("T1", new NetworkSimulator("T1", 3, 1544000/10, 1544000/10));
        _simulators.put("DSL (384k down, 128k up)", new NetworkSimulator("DSL (384k down, 128k up)", 10, 128*1024/10, 384*1024/10));
        _simulators.put("Bonded ISDN", new NetworkSimulator("Bonded ISDN", 20, 128*1024/10, 128*1024/10));
        _simulators.put("ISDN", new NetworkSimulator("ISDN", 20, 64*1024/10, 64*1024/10));
        _simulators.put("56k modem", new NetworkSimulator("56k modem", 200, 33600/10, 56000/10));
        _simulators.put("28k modem", new NetworkSimulator("28k modem", 200, 28800/10));
    }
    
    private void createListeners() {
        String prop = "Proxy.listeners";
        String value = Preferences.getPreference(prop);
        if (value == null || value.trim().equals("")) {
            _logger.warning("No proxies configured!?");
            value = "127.0.0.1:8008";
        }
        String[] listeners = value.trim().split(" *,+ *");
        
        String addr;
        int port = 0;
        HttpUrl base;
        String simulator = null;
        boolean primary = false;
        
        for (int i=0; i<listeners.length; i++) {
            addr = listeners[i].substring(0, listeners[i].indexOf(":"));
            try {
                port = Integer.parseInt(listeners[i].substring(listeners[i].indexOf(":")+1).trim());
            } catch (NumberFormatException nfe) {
                System.err.println("Error parsing port for " + listeners[i] + ", skipping it!");
                continue;
            }
            prop = "Proxy.listener." + listeners[i] + ".base";
            value = Preferences.getPreference(prop, "");
            if (value.equals("")) {
                base = null;
            } else {
                try {
                    base = new HttpUrl(value);
                } catch (MalformedURLException mue) {
                    _logger.severe("Malformed 'base' parameter for listener '"+listeners[i]+"'");
                    break;
                }
            }
            
            prop = "Proxy.listener." + listeners[i] + ".simulator";
            value = Preferences.getPreference(prop, "Unlimited");
            
            if (!value.trim().equals("") && _simulators.containsKey(value)) {
                simulator = value;
            } else {
                _logger.warning("Unknown network simulator '" + value + "'");
            }
            
            prop = "Proxy.listener." + listeners[i] + ".primary";
            value = Preferences.getPreference(prop, "false");
            primary = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
            
            try {
                Listener l = createListener(addr, port, base, simulator, primary);
            } catch (IOException ioe) {
                _logger.severe("Error starting proxy (" + addr + ":" + port + " " + base + " " + ioe);
            }
        }
    }
    
    private Listener createListener(String address, int port, HttpUrl base, String simulator, boolean primaryProxy) throws IOException {
        if (base != null && base.equals("")) {
            base = null;
        }
        if (simulator == null || simulator.trim().equals("") || !_simulators.containsKey(simulator)) {
            simulator = "Unlimited";
        }
        NetworkSimulator netsim = (NetworkSimulator) _simulators.get(simulator);
        
        Listener l = new Listener(this, address, port);
        l.setBase(base);
        l.setSimulator(netsim);
        l.setPrimaryProxy(primaryProxy);
        
        String key = l.getKey();
        _listeners.put(key, l);
        
        if (_ui != null) _ui.proxyAdded(key);
        
        return l;
    }
    
    public void flush() throws StoreException {
        // we do not run our own store, but our plugins might
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            ProxyPlugin plugin = (ProxyPlugin) it.next();
            plugin.flush();
        }
    }
    
    public boolean isBusy() {
        return _pending > 0;
    }
    
    public String getStatus() {
        return _status;
    }
    
    public boolean isModified() {
        return false;
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        // we do no analysis
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
        // we have no listeners to remove
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            ProxyPlugin plugin = (ProxyPlugin) it.next();
            plugin.setSession(type, store, session);
        }
    }
    
    public boolean isRunning() {
        return _running;
    }
    
    private class ConnectionHook extends Hook {
        
        public ConnectionHook(String name, String description) {
            super(name, description);
        }
        
        public void runScripts(ScriptableConnection connection) {
            if (_bsfManager == null) return;
            synchronized(_bsfManager) {
                try {
                    _bsfManager.declareBean("connection", connection, connection.getClass());
                    super.runScripts();
                    _bsfManager.undeclareBean("connection");
                } catch (Exception e) {
                    _logger.severe("Declaring or undeclaring a bean should not throw an exception! " + e);
                }
            }
        }
        
    }
    
}
