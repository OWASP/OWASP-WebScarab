/*
 * $Id: Proxy.java,v 1.17 2004/12/15 10:05:24 rogan Exp $
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;

import java.lang.NumberFormatException;
import java.util.ArrayList;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.logging.Logger;

import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.Plugin;

import java.net.MalformedURLException;

/**
 * The Proxy plugin supports multiple Listeners, and starts and stops them as
 * instructed. All requests and responses are submitted to the model, unless there
 * is an error while retrieving the response.
 */
public class Proxy extends Plugin {
    
    private SiteModel _model = null;
    
    private ProxyUI _ui = null;
    
    private ArrayList _plugins = new ArrayList();
    private TreeMap _listeners = new TreeMap();
    private TreeMap _simulators = new TreeMap();
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private String _status = "Stopped";
    private int _pending = 0;
    
    /**
     * Creates a Proxy Object with a reference to the SiteModel. Creates (but does not
     * start) the configured Listeners.
     * @param model The Model to submit requests and responses to
     */
    public Proxy() {
        createSimulators();
        createListeners();
    }
    
    public void setSession(SiteModel model, String type, Object connection) {
        // we have no listeners to remove
        _model = model;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            ProxyPlugin plugin = (ProxyPlugin) it.next();
            plugin.setModel(model, type, connection);
        }
        if (_ui != null) _ui.setModel(model);
    }
    
    public void setUI(ProxyUI ui) {
        _ui = ui;
        if (_ui != null) _ui.setEnabled(_running);
    }
    
    public void addPlugin(ProxyPlugin plugin) {
        _plugins.add(plugin);
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
    
    /**
     *
     * @param key
     * @return
     */
    public boolean usesPlugins(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.usesPlugins();
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
    
    public void addListener(String address, int port, HttpUrl base, String simulator, boolean usePlugins) throws IOException {
        Listener l = createListener(address, port, base, simulator, usePlugins);
        startListener(l);
        
        String key = l.getKey();
        Preferences.setPreference("Proxy.listener." + key + ".base", base == null ? "" : base.toString());
        Preferences.setPreference("Proxy.listener." + key + ".useplugins", usePlugins == true ? "yes" : "no");
        Preferences.setPreference("Proxy.listener." + key + ".simulator", simulator);
        
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
            Preferences.remove("Proxy.listener." + key + ".useplugins");
            Preferences.remove("Proxy.listener." + key + ".simulator");
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
        ConversationID id = _model.reserveConversationID();
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
        _model.addConversation(id, response.getRequest(), response, getPluginName());
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
        boolean usePlugins = false;
        String simulator = null;
        
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
            
            prop = "Proxy.listener." + listeners[i] + ".useplugins";
            value = Preferences.getPreference(prop, "true");
            
            if (value == null || value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes")) {
                usePlugins = true;
            } else {
                usePlugins = false;
            }
            
            prop = "Proxy.listener." + listeners[i] + ".simulator";
            value = Preferences.getPreference(prop, "Unlimited");
            
            if (!value.trim().equals("") && _simulators.containsKey(value)) {
                simulator = value;
            } else {
                _logger.warning("Unknown network simulator '" + value + "'");
            }
            
            try {
                Listener l = createListener(addr, port, base, simulator, usePlugins);
            } catch (IOException ioe) {
                _logger.severe("Error starting proxy (" + addr + ":" + port + " " + base + " " + ioe);
            }
        }
    }
    
    private Listener createListener(String address, int port, HttpUrl base, String simulator, boolean usePlugins) throws IOException {
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
        l.usePlugins(usePlugins);
        
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
    
}
