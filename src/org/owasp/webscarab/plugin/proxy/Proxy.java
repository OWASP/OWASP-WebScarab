package org.owasp.webscarab.plugin.proxy;

/*
 * $Id: Proxy.java,v 1.5 2003/08/25 22:21:07 rogan Exp $
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.SocketException;

import java.io.IOException;
import java.io.FileNotFoundException;

import java.lang.NumberFormatException;
import java.util.logging.Logger;
import java.util.ArrayList;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

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
    
    public void setSessionStore(Object store) throws StoreException {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].setSessionStore(store);
        }
    }

    public void saveSessionData() throws StoreException {
        // we keep no state of our own, but maybe the plugins do?
        for (int i=0; i<_pluginArray.length; i++) {
            _pluginArray[i].saveSessionData();
        }
    }

}
