/*
 * Listener.java
 *
 * Created on August 30, 2003, 4:15 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.lang.Runnable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.io.IOException;
import java.lang.Thread;

import java.util.logging.Logger;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public class Listener implements Runnable {
    
    private Proxy _proxy;
    private String _address;
    private int _port;
    private HttpUrl _base = null;
    private NetworkSimulator _simulator = null;
    private boolean _usePlugins = false;
    
    private ServerSocket _serversocket = null;

    private boolean _stop = false;
    private boolean _stopped = true;
    
    private InetAddress _addr;
    
    private int _count = 1;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of Listener */
    public Listener(Proxy proxy, String address, int port) throws IOException {
        _proxy = proxy;
        if (address == null) {
            address = "*";
        }
        _address = address;
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 0 and 65536");
        }
        _port = port;
        if (_address.equals("") || _address.equals("*")) {
            _addr = null;
        } else {
            _addr = InetAddress.getByName(_address);
        }
        // make sure we can listen on the port
        _serversocket = new ServerSocket(_port, 5, _addr);
        _serversocket.close();
    }

    public void run() {
        _stop = false;
        _stopped = false;
        Socket sock;
        ConnectionHandler ch;
        Thread thread;
        if (_serversocket == null || _serversocket.isClosed()) {
            try {
                listen();
            } catch (IOException ioe) {
                _logger.severe("Can't listen at " + getKey() + ": " + ioe);
                _stopped = true;
                return;
            }
        }
        while (! _stop) {
            try {
                sock = _serversocket.accept();
                _logger.info("Connect from " + sock.getInetAddress().getHostAddress() + ":" + sock.getPort());
                ch = new ConnectionHandler(this, sock, _base, _simulator, _usePlugins);
                thread = new Thread(ch, Thread.currentThread().getName()+"-"+Integer.toString(_count++));
                thread.setDaemon(true);
                thread.start();
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
        _logger.info("Not listening on " + getKey());
    }
    
    private void listen() throws IOException {
        _serversocket = new ServerSocket(_port, 5, _addr);
        
        _logger.info("Proxy listening on " + getKey());
        
        try {
            _serversocket.setSoTimeout(100);
        } catch (SocketException se) {
            _logger.warning("Error setting sockettimeout " + se);
            _logger.warning("It is likely that this listener will be unstoppable!");
        }
    }
    
    public boolean stop() {
        _stop = true;
        if (!_stopped) {
            for (int i=0; i<20; i++) {
                try {
                    Thread.sleep(100);
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
    
    public void setBase(HttpUrl base) {
        _base = base;
    }
    
    public HttpUrl getBase() {
        return _base;
    }
    
    public void setSimulator(NetworkSimulator simulator) {
        _simulator = simulator;
    }
    
    public NetworkSimulator getSimulator() {
        return _simulator;
    }
    
    public void usePlugins(boolean usePlugins) {
        _usePlugins = usePlugins;
    }
    
    public boolean usesPlugins() {
        return _usePlugins;
    }
    
    public String getKey() {
        return _address + ":" + _port;
    }
    
    /**
     * used by ConnectionHandler to notify the Proxy (and any listeners) that it is
     * handling a particular request
     * @param request the request to log
     * @return the conversation ID
     */
    protected ConversationID gotRequest(Request request) {
        return _proxy.gotRequest(request);
    }
    
    /**
     * used by ConnectionHandler to notify the Proxy (and any listeners) that it has
     * handled a particular request and response, and that it should be logged and
     * analysed
     * @param id the Conversation ID
     * @param response the Response
     */
    protected void gotResponse(ConversationID id, Response response) {
    	_proxy.gotResponse(id, response);
    }
    
    /**
     * notifies any observers that the request failed to complete, and the reason for it
     * @param reason the reason for failure
     * @param id the conversation ID
     */
    protected void failedResponse(ConversationID id, String reason) {
        _proxy.failedResponse(id, reason);
    }
    
    /**
     * called by ConnectionHandler to see which plugins have been configured.
     * @return an array of ProxyPlugin's
     */
    protected ProxyPlugin[] getPlugins() {
    	return _proxy.getPlugins();
    }
    
}
