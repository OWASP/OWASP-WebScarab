package org.owasp.webscarab.plugin.proxy;

/*
 * $Id: Proxy.java,v 1.8 2003/09/11 20:47:57 rogan Exp $
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
        
        _prop = plug.getProperties();
        if (_prop.getProperty("Proxy.listeners") == null) {
            startProxy("127.0.0.1", 8008, null, true);
            startProxy("127.0.0.1", 8009, null, false);
        } else {
            parseProperties();
        }
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
            String value = _prop.getProperty("Proxy.listeners");
            if (value == null) {
                value = key;
            } else {
                value = value + ", " + key;
            }
            _prop.setProperty("Proxy.listeners", value);
            _prop.setProperty("Proxy.listener." + key + ".base", base == null ? "" : base);
            _prop.setProperty("Proxy.listener." + key + ".useplugins", usePlugins == true ? "yes" : "no");
            return key;
        } catch (Exception e) {
            System.out.println("Exception starting the proxy : " + e);
            return null;
        }
    }
    
    public boolean stopProxy(String key) {
        System.out.println("listeners is " + _listeners);
        System.out.println("Key is " + key);
        Listener l = (Listener) _listeners.remove(key);
        System.out.println("l is " + l);
        if (l != null && l.stop()) {
            String listeners = _prop.getProperty("Proxy.listeners");
            int index = listeners.indexOf(key);
            if (index>0) {
                listeners = listeners.replaceFirst(", *" + key, "");
            } else {
                listeners = listeners.substring(key.length()+1);
            }
            _prop.setProperty("Proxy.listeners", listeners);
            _prop.remove("Proxy.listener." + key + ".base");
            _prop.remove("Proxy.listener." + key + ".useplugins");
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
