/*
 * Listener.java
 *
 * Created on August 30, 2003, 4:15 PM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.plugin.Plug;

import java.lang.Runnable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.io.IOException;
import java.lang.Thread;

import java.util.ArrayList;

/**
 *
 * @author  rdawes
 */
public class Listener implements Runnable {
    
    private Plug _plug;
    private String _address;
    private int _port;
    private String _base;
    private ArrayList _plugins;
    
    private ServerSocket _serversocket;

    private boolean _stop = false;
    private boolean _stopped = true;
    
    
    /** Creates a new instance of Listener */
    public Listener(Plug plug, String address, int port, String base, ArrayList plugins) throws UnknownHostException, IOException {
        _plug = plug;
        
        if (address == null) {
            address = "*";
        }
        _address = address;
        InetAddress addr;
        if (address.equals("") || address.equals("*")) {
            addr = null;
        } else {
            addr = InetAddress.getByName(address);
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 0 and 65536");
        }
        _port = port;
        if (base != null) {
            if (! base.startsWith("http")) {
                throw new IllegalArgumentException("base must be null, or an http or https url");
            }
        }
        _base = base;
        _plugins = plugins;
        _serversocket = new ServerSocket(port, 5, addr);
        
        System.err.println("Proxy listening on " + address + ":" + port);
        
        try {
            _serversocket.setSoTimeout(100);
        } catch (SocketException se) {
            System.err.println("Error setting sockettimeout " + se);
            System.err.println("It is likely that this listener will be unstoppable!");
        }
        Thread t = new Thread(this);
        t.setDaemon(false);
        t.start();
    }
    
    public void run() {
        _stopped = false;
        Socket sock;
        while (! _stop) {
            try {
                sock = _serversocket.accept();
                System.err.println("Connect from " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
                new ConnectionHandler(sock, _plug, _base, _plugins);
            } catch (IOException e) {
                if (!e.getMessage().equals("Accept timed out")) {
                    System.err.println("I/O error while waiting for a connection : " + e.getMessage());
                }
            }
        }
        _stopped = true;
        try {
            _serversocket.close();
        } catch (IOException ioe) {
            System.err.println("Error closing socket : " + ioe);
        }
    }
    
    public boolean stop() {
        _stop = true;
        if (!_stopped) {
            for (int i=0; i<20; i++) {
                try {
                    Thread.currentThread().sleep(100);
                } catch (InterruptedException ie) {}
                if (_stopped) {
                    return true;
                }
            }
            return false;
        } else {
            return true;
        }
    }

    public String getAddress() {
        return _address;
    }
    
    public int getPort() {
        return _port;
    }
    
    public String getBase() {
        return _base;
    }
    
    public ArrayList getPlugins() {
        return _plugins;
    }

}
