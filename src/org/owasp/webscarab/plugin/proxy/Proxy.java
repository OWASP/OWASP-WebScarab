package org.owasp.webscarab.plugin.proxy;

/*
 * $Id: Proxy.java,v 1.9 2003/09/15 08:15:05 rogan Exp $
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

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.CookieJar;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

public class Proxy extends AbstractWebScarabPlugin {
    
    private Plug _plug = null;
    
    private ArrayList _plugins = new ArrayList();
    private TreeMap _listeners = new TreeMap();
    
    public Proxy(Plug plug) {
        _plug = plug;
        
        if (_prop.getProperty("Proxy.listeners") == null) {
            setDefaultProperty("Proxy.listeners", "127.0.0.1:8008, 127.0.0.1:8009");
            setDefaultProperty("Proxy.listener.127.0.0.1:8008.base", "");
            setDefaultProperty("Proxy.listener.127.0.0.1:8008.useplugins", "yes");
            setDefaultProperty("Proxy.listener.127.0.0.1:8009.base", "");
            setDefaultProperty("Proxy.listener.127.0.0.1:8009.useplugins", "no");
        }
        parseProperties();
        System.err.println("Proxy initialised");
    }
    
    private void parseProperties() {
        String prop = "Proxy.listeners";
        String value = _prop.getProperty(prop).trim();
        String[] listeners = value.split(" *,+ *");
        
        String addr;
        int port = 0;
        String base;
        boolean usePlugins = false;
        
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
            
            startProxy(addr, port, base, usePlugins);
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

    public boolean getPlugins(String key) {
        Listener l = (Listener) _listeners.get(key);
        if (l != null) {
            return (l.getPlugins() != null);
        } else {
            return false;
        }
    }

    public String startProxy(String address, int port, String base, boolean usePlugins) {
        String key = address + ":" + port;
        try {
            if (base != null && base.equals("")) {
                base = null;
            }
            Listener l = new Listener(_plug, address, port, base, usePlugins ? _plugins : null);
            _listeners.put(key,l);
            
            _prop.setProperty("Proxy.listener." + key + ".base", base == null ? "" : base);
            _prop.setProperty("Proxy.listener." + key + ".useplugins", usePlugins == true ? "yes" : "no");
            
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
        } catch (Exception e) {
            System.out.println("Exception starting the proxy : " + e);
            return null;
        }
    }
    
    public boolean stopProxy(String key) {
        Listener l = (Listener) _listeners.remove(key);
        if (l != null && l.stop()) {
            _prop.remove("Proxy.listener." + key + ".base");
            _prop.remove("Proxy.listener." + key + ".useplugins");
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
