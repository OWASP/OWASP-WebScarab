package org.owasp.webscarab.plugin.proxy;

/*
 * $Id: Proxy.java,v 1.11 2004/05/20 06:37:29 rogan Exp $
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.SocketException;

import java.io.IOException;
import java.io.FileNotFoundException;

import java.lang.NumberFormatException;
import java.util.ArrayList;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.logging.Logger;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.CookieJar;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

public class Proxy extends AbstractWebScarabPlugin {
    
    private Plug _plug = null;
    
    private ArrayList _plugins = new ArrayList();
    private TreeMap _listeners = new TreeMap();
    private TreeMap _simulators = new TreeMap();
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    public Proxy(Plug plug) {
        _plug = plug;
        
        _simulators.put("Unlimited", new NetworkSimulator("Unlimited", 0, Integer.MAX_VALUE, Integer.MAX_VALUE));
        _simulators.put("56k modem", new NetworkSimulator("56k modem", 200, 3300, 5600));
        _simulators.put("28k modem", new NetworkSimulator("28k modem", 200, 2880));
        
        parseProperties();
        _logger.info("Proxy initialised");
    }
    
    private void parseProperties() {
        String prop = "Proxy.listeners";
        String value = _prop.getProperty(prop);
        if (value == null || value.trim().equals("")) {
            _logger.warning("No proxies configured!?");
            return;
        }
        String[] listeners = value.trim().split(" *,+ *");
        
        String addr;
        int port = 0;
        String base;
        boolean usePlugins = false;
        String simulator = null;
        
        for (int i=0; i<listeners.length; i++) {
            addr = listeners[i].substring(0, listeners[i].indexOf(":"));
            try {
                port = Integer.parseInt(listeners[i].substring(listeners[i].indexOf(":")+1));
            } catch (NumberFormatException nfe) {
                System.err.println("Error parsing port for " + listeners[i] + ", skipping it!");
                continue;
            }
            prop = "Proxy.listener." + listeners[i] + ".base";
            base = _prop.getProperty(prop);
            if (base != null && base.equals("")){
                base = null;
            }
            
            prop = "Proxy.listener." + listeners[i] + ".useplugins";
            value = _prop.getProperty(prop);
            
            if (value == null) {
                usePlugins = false;
            } else if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes")) {
                usePlugins = true;
            } else {
                usePlugins = false;
            }
            
            prop = "Proxy.listener." + listeners[i] + ".simulator";
            value = _prop.getProperty(prop);
            
            if ((value != null) && !value.trim().equals("") && _simulators.containsKey(value)) {
                simulator = value;
            } else {
                _logger.warning("Unknown network simulator '" + value + "'");
            }
            
            try { 
                startProxy(addr, port, base, simulator, usePlugins);
            } catch (IOException ioe) {
                _logger.severe("Error starting proxy (" + addr + ":" + port + " " + base + " " + ioe);
            }
        }
    }
    
    public String[] getProxies() {
        if (_listeners.size()==0) {
            return new String[0];
        }
        return (String[]) _listeners.keySet().toArray(new String[0]);
    }
    
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
    
    public String getBase(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.getBase();
        } else {
            return null;
        }
    }
    
    public String[] getSimulators() {
        return (String[])_simulators.keySet().toArray(new String[0]);
    }
    
    public String getSimulator(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return l.getSimulator();
        } else {
            return "";
        }
    }
    
    public boolean getPlugins(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return (l.getPlugins() != null);
        } else {
            return false;
        }
    }
    
    public String startProxy(String address, int port, String base, String simulator, boolean usePlugins) throws IOException {
        String key = address + ":" + port;
            if (base != null && base.equals("")) {
                base = null;
            }
            if (simulator == null || simulator.trim().equals("") || !_simulators.containsKey(simulator)) {
                simulator = "Unlimited";
            }
            NetworkSimulator netsim = (NetworkSimulator) _simulators.get(simulator);
            ProxyPlugin[] plugins = new ProxyPlugin[_plugins.size()];
            plugins = (ProxyPlugin[]) _plugins.toArray(plugins);
            Listener l = new Listener(_plug, address, port, base, netsim, usePlugins ? plugins : null);
            _listeners.put(key,l);
            
            _prop.setProperty("Proxy.listener." + key + ".base", base == null ? "" : base);
            _prop.setProperty("Proxy.listener." + key + ".useplugins", usePlugins == true ? "yes" : "no");
            _prop.setProperty("Proxy.listener." + key + ".simulator", simulator);
            
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
            _prop.setProperty("Proxy.listeners", value);
            return key;
    }
    
    public boolean stopProxy(String key) {
        Listener l = (Listener) _listeners.remove(key);
        if (l != null && l.stop()) {
            _prop.remove("Proxy.listener." + key + ".base");
            _prop.remove("Proxy.listener." + key + ".useplugins");
            _prop.remove("Proxy.listener." + key + ".simulator");
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
            _prop.setProperty("Proxy.listeners", value);
            return true;
        } else {
            return false;
        }
    }
    
    public void addPlugin(ProxyPlugin plugin) {
        _plugins.add(plugin);
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Proxies");
    }
    
    public CookieJar getCookieJar() {
        return _plug.getCookieJar();
    }
    
    public void setSessionStore(Object store) throws StoreException {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_plugins.size(); i++) {
            ((ProxyPlugin)_plugins.get(i)).setSessionStore(store);
        }
    }
    
    public void saveSessionData() throws StoreException {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_plugins.size(); i++) {
            ((ProxyPlugin)_plugins.get(i)).saveSessionData();
        }
    }
    
}
