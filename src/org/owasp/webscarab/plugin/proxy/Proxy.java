package org.owasp.webscarab.plugin.proxy;

/*
 * $Id: Proxy.java,v 1.3 2003/08/07 21:53:31 rogan Exp $
 */
import java.net.*;
import java.io.*;
import java.lang.NumberFormatException;
import java.util.logging.Logger;
import java.util.ArrayList;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;
import org.owasp.webscarab.model.*;

import org.owasp.webscarab.plugin.proxy.module.*;

public class Proxy
	extends AbstractWebScarabPlugin
	implements Runnable
{
    
    private Plug _plug = null;
    
    private ArrayList _plugins = null;
    private ProxyPlugin[] _pluginArray = new ProxyPlugin[0];
    
    private boolean portChanged = false;
    
    private String listenHost = null;
    private int listenPort = 0;
    
    private ServerSocket serversocket;
    private Logger logger = Logger.getLogger("Plug.Proxy");
    
    public Proxy(Plug plug) {
        _plug = plug;
        _prop.put("Proxy.listenAddress", "127.0.0.1:8008");
        configure();
    }
    
    protected void configure() {
        String prop = "Proxy.listenAddress";
        String value = _prop.get(prop);
        String[] listenAddress = value.split(":");
        if (listenAddress.length == 2) {
            try {
                setListenAddress(listenAddress[0], Integer.parseInt(listenAddress[1]));
            } catch (NumberFormatException nfe) {
                System.out.println("Error parsing property '" + prop + "' = '" + value + "'");
            }
        } else {
            logger.severe("Error parsing property '" + prop + "' = '" + value + "'");
	}
    }

    public void setListenAddress(String server, int port) {
        if (port > 0 && port != this.listenPort || !server.equals(listenHost)) {
            this.listenPort = port;
            this.listenHost = server;
            this.portChanged = true;
            _prop.put("Proxy.listenAddress",server + ":" + port);
        }
    }
    
    public String getListenServer() {
        return listenHost;
    }
    
    public int getListenPort() {
        return listenPort;
    }
    
    public void addPlugin(ProxyPlugin plugin) {
        if (_plugins == null) {
            _plugins = new ArrayList();
        }
        _plugins.add(plugin);
        _pluginArray = (ProxyPlugin[]) _plugins.toArray(_pluginArray);
    }
    
    public void run() {
        Socket sock;

        while (true) {
            portChanged = false;
            serversocket = null;
            while (serversocket == null) {
                try {
                    synchronized (listenHost) {
                        InetAddress addr = null;
                        if (!listenHost.equals("") && !listenHost.equals("*")) {
                            addr = InetAddress.getByName(listenHost);
                        }
                        logger.info("Listening on " + listenHost + ":" + listenPort);
                        serversocket = new ServerSocket(listenPort, 5, addr);
                    }
                } catch (Exception e) {
                    logger.severe("Could not bind to " + listenHost + ":" + listenPort + " : " + e);
                    logger.severe("sleeping for 5 seconds while you do something about it");
                    try {
                        Thread.currentThread().sleep(5000);
                    } catch (InterruptedException ie) {}
                }
            }
            try {
                serversocket.setSoTimeout(100);
            } catch (SocketException se) {
                logger.info("Error setting sockettimeout " + se);
            }
            logger.info("Proxy server started");
            while (! portChanged) {
                try {
                    sock = serversocket.accept();
                    logger.info("Connect from " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
                    new ConnectionHandler(sock, _plug, null, _pluginArray);
                } catch (IOException e) {
                    if (!e.getMessage().equals("Accept timed out")) {
                        logger.severe("I/O error while waiting for a connection : " + e.getMessage());
                    }
                }
            }
            logger.info("ListenPort was changed. Closing and re-opening the socket");
            try {
                serversocket.close();
            } catch (IOException ioe) {
                logger.severe("Error closing the listen socket");
            }
        }
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Proxy");
    }
    
    /** called to create any directory structures required by this plugin.
     * @param dir a String representing the base directory under which this session's 
     * data will be saved
     */    
    public void initDirectory(String dir) {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].initDirectory(dir);
        }
    }
    
    /** Instructs the plugin to discard any session specific data that it may hold */
    public void discardSessionData() {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].discardSessionData();
        }
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void saveSessionData(String dir) {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].saveSessionData(dir);
        }
    }
    
    /** called to instruct the plugin to read any saved state data from the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void loadSessionData(String dir) {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].loadSessionData(dir);
        }
    }

}
