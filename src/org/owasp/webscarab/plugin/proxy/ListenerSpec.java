/**
 * 
 */
package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;

import org.owasp.webscarab.model.HttpUrl;

/**
 * @author rdawes
 *
 */
public class ListenerSpec implements Comparable<Object> {

    private String _address;
    private int _port;
    private HttpUrl _base = null;
    private boolean _primaryProxy = false;

    private InetSocketAddress _sockAddr = null;
    
    public ListenerSpec(String address, int port, HttpUrl base, boolean primaryProxy) {
        if (address == null) {
            address = "*";
        }
        _address = address;
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 0 and 65536");
        }
        _port = port;
        _base = base;
        _primaryProxy = primaryProxy;
    }
    
    public String getAddress() {
        return _address;
    }
    
    public int getPort() {
        return _port;
    }
    
    public HttpUrl getBase() {
        return _base;
    }
    
    public boolean isPrimaryProxy() {
        return _primaryProxy;
    }
    
    public String getKey() {
        return _address + ":" + _port;
    }
    
    public int hashCode() {
        return toString().hashCode();
    }
    
    public String toString() {
        return _address + ":" + _port + (_base != null ? " => " + _base : "") + (_primaryProxy ? " Primary" : "");
    }
    
    public boolean equals(Object obj) {
        return toString().equals(obj.toString());
    }
    
    public InetSocketAddress getInetSocketAddress() {
        if (_sockAddr == null) {
            _sockAddr = new InetSocketAddress(_address, _port);
        }
        return _sockAddr;
    }
    
    public void verifyAvailable() throws IOException {
        // make sure we can listen on the port
        InetSocketAddress sa = getInetSocketAddress();
        ServerSocket serversocket = new ServerSocket(sa.getPort(), 5, sa.getAddress());
        serversocket.close();
    }

    /* (non-Javadoc)
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    public int compareTo(Object o) {
        return toString().compareTo(o.toString());
    }
    
    
}
