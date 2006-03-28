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
 * URLFetcher.java
 *
 * Created on April 12, 2003, 1:31 AM
 */

package org.owasp.webscarab.httpclient;

import java.io.IOException;

import java.net.Socket;
import java.net.InetSocketAddress;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;

import java.util.logging.Logger;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;
import jcifs.util.Base64;

import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.util.Glob;

/** Creates a new instance of URLFetcher
 * @author rdawes
 */
public class URLFetcher implements HTTPClient {
    
    private static SocketWatcher watcher = new SocketWatcher();
    
    // These represent the SSL classes required to connect to the server.
    private String _keyFingerprint = null;
    private SSLContextManager _sslContextManager = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _httpProxy = "";
    private int _httpProxyPort = -1;
    private String _httpsProxy = "";
    private int _httpsProxyPort = -1;
    private String[] _noProxy = new String[0];
    
    private Socket _socket = null;
    private boolean _direct = false;
    private Response _response = null;
    
    // these represent an already connected socket, and the end point thereof.
    private InputStream _in = null;
    private OutputStream _out = null;
    private String _host = null;
    private int _port = 0;
    private long _lastRequestTime = 0;
    
    private int _timeout = 0;
    private int _connectTimeout = 10000;
    
    private Authenticator _authenticator = null;
    private String _authCreds = null;
    private String _proxyAuthCreds = null;
    
    /** Creates a new instance of URLFetcher
     */
    public URLFetcher() {
    }
    
    /** Tells URLFetcher which HTTP proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTP requests
     * @param proxyport The port on the proxy server to connect to
     */
    public void setHttpProxy(String proxy, int proxyport) {
        _httpProxy = proxy;
        if (_httpProxy == null) _httpProxy = "";
        _httpProxyPort = proxyport;
    }
    
    /** Tells URLFetcher which HTTPS proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTPS requests
     * @param proxyport The port on the proxy server to connect to
     */
    public void setHttpsProxy(String proxy, int proxyport) {
        _httpsProxy = proxy;
        if (_httpsProxy == null) _httpsProxy = "";
        _httpsProxyPort = proxyport;
    }
    
    /** Accepts an array of hostnames or domains for which no proxy should be used.
     * if the hostname begins with a period ("."), than all hosts in that domain will
     * ignore the configured proxies
     * @param noproxy An array of hosts or domains for which no proxy should be used.
     * Domains must start with a period (".")
     */
    public void setNoProxy(String[] noproxy) {
        if (noproxy == null) {
            _noProxy = new String[0];
        } else if (noproxy.length == 0) {
            _noProxy = noproxy;
        } else {
            _noProxy = new String[noproxy.length];
            System.arraycopy(noproxy, 0, _noProxy, 0, noproxy.length);
        }
    }
    
    public void setSSLContextManager(SSLContextManager sslContextManager) {
        _sslContextManager = sslContextManager;
    }
    
    public void setTimeouts(int connectTimeout, int readTimeout) {
        _connectTimeout = connectTimeout;
        _timeout = readTimeout;
    }
    
    public void setAuthenticator(Authenticator authenticator) {
        _authenticator = authenticator;
    }
    
    public Authenticator getAuthenticator() {
        return _authenticator;
    }
    
    /** Can be used by a calling class to fetch a request without spawning an additional
     * thread. This is appropriate when the calling class is already running in an
     * independant thread, and must wait for the response before continuing.
     * @return the retrieved response
     * @param request the request to retrieve.
     */
    public Response fetchResponse(Request request) throws IOException {
        if (_response != null) {
            _response.flushContentStream(); // flush the content stream, just in case it wasn't read
            _response = null;
        }
        if (request == null) {
            _logger.severe("Asked to fetch a null request");
            return null;
        }
        HttpUrl url = request.getURL();
        if (url == null) {
            _logger.severe("Asked to fetch a request with a null URL");
            return null;
        }
        
        // if the previous auth method was not "Basic", force a new connection
        if (_authCreds != null && !_authCreds.startsWith("Basic"))
            _lastRequestTime = 0;
        if (_proxyAuthCreds != null && !_proxyAuthCreds.startsWith("Basic")) 
            _lastRequestTime = 0;
        
        // Get any provided credentials from the request
        _authCreds = request.getHeader("Authorization");
        
        String keyFingerprint = request.getHeader("X-SSLClientCertificate");
        request.deleteHeader("X-SSLClientCertificate");
        if (keyFingerprint == null && _keyFingerprint == null) {
            // no problem
        } else if (keyFingerprint != null && _keyFingerprint != null && keyFingerprint.equals(_keyFingerprint)) {
            // no problem
        } else {
            // force a new connection, and change the fingerprint
            _keyFingerprint = keyFingerprint;
            _lastRequestTime = 0;
        }
        
        String status;
        
        String oldProxyAuthHeader = null;
        if (_proxyAuthCreds == null && _authenticator!= null && useProxy(url))
            _proxyAuthCreds = _authenticator.getProxyCredentials(url.toString().startsWith("https") ? _httpsProxy : _httpProxy, null);
        String proxyAuthHeader = constructAuthenticationHeader(null, _proxyAuthCreds);
        
        String oldAuthHeader = null;
        if (_authCreds == null && _authenticator!= null)
            _authCreds = _authenticator.getCredentials(url, null);
        String authHeader = constructAuthenticationHeader(null, _authCreds);
        
        int tries = 0;
        do {
            // make sure that we have a "clean" request each time through
            request.deleteHeader("Authorization");
            request.deleteHeader("Proxy-Authorization");
            
            _response = null;
            connect(url);
            if (_response != null) { // there was an error opening the socket
                return _response;
            }
            
            if (authHeader != null) {
                request.setHeader("Authorization", authHeader);
                if (authHeader.startsWith("NTLM") || authHeader.startsWith("Negotiate")) {
                    if (request.getVersion().equals("HTTP/1.0")) {
                        // we have to explicitly tell the server to keep the connection alive for 1.0
                        request.setHeader("Connection", "Keep-Alive");
                    } else {
                        request.deleteHeader("Connection");
                    }
                }
            }
            // depending on whether we are connected directly to the server, or via a proxy
            if (_direct) {
                request.writeDirect(_out);
            } else {
                if (proxyAuthHeader != null) {
                    request.setHeader("Proxy-Authorization", proxyAuthHeader);
                    if (proxyAuthHeader.startsWith("NTLM") || proxyAuthHeader.startsWith("Negotiate")) {
                        if (request.getVersion().equals("HTTP/1.0")) {
                            // we have to explicitly tell the server to keep the connection alive for 1.0
                            request.setHeader("Connection", "Keep-Alive");
                        } else {
                            request.deleteHeader("Connection");
                        }
                    }
                }
                request.write(_out);
            }
            _out.flush();
            _logger.finest("Request : \n" + request.toString());
            
            _response = new Response();
            _response.setRequest(request);
            
            // test for spurious 100 header from IIS 4 and 5.
            // See http://mail.python.org/pipermail/python-list/2000-December/023204.html
            _logger.fine("Reading the response");
            do {
                _response.read(_in);
                status = _response.getStatus();
            } while (status.equals("100"));
            
            {
                StringBuffer buff = new StringBuffer();
                buff.append(_response.getStatusLine()).append("\n");
                NamedValue[] headers = _response.getHeaders();
                if (headers != null)
                    for (int i=0; i< headers.length; i++)
                        buff.append(headers[i].getName()).append(": ").append(headers[i].getValue()).append("\n");
                _logger.finest("Response:\n" + buff.toString());
            }
            
            if (status.equals("407")) {
                _response.flushContentStream();
                oldProxyAuthHeader = proxyAuthHeader;
                String[] challenges = _response.getHeaders("Proxy-Authenticate");
                if (_proxyAuthCreds == null && _authenticator != null) {
                    _proxyAuthCreds = _authenticator.getProxyCredentials(_httpProxy, challenges);
                }
                proxyAuthHeader = constructAuthenticationHeader(challenges, _proxyAuthCreds);
                if (proxyAuthHeader != null && oldProxyAuthHeader != null && oldProxyAuthHeader.equals(proxyAuthHeader)) {
                    _logger.info("No possible authentication");
                    proxyAuthHeader = null;
                }
            }
            
            if (status.equals("401")) {
                _response.flushContentStream();
                oldAuthHeader = authHeader;
                String[] challenges = _response.getHeaders("WWW-Authenticate");
                if (_authCreds == null && _authenticator != null)
                    _authCreds = _authenticator.getCredentials(url, challenges);
                _logger.finer("Auth creds are " + _authCreds);
                authHeader = constructAuthenticationHeader(challenges, _authCreds);
                _logger.finer("Auth header is " + authHeader);
                if (authHeader != null && oldAuthHeader != null && oldAuthHeader.equals(authHeader)) {
                    _logger.info("No possible authentication");
                    authHeader = null;
                }
            }
            
            // if the request method is HEAD, we get no contents, EVEN though there
            // may be a Content-Length header.
            if (request.getMethod().equals("HEAD")) _response.setNoBody();
            
            _logger.info(request.getURL() +" : " + _response.getStatusLine());
            
            String connection = _response.getHeader("Proxy-Connection");
            if (connection != null && "close".equalsIgnoreCase(connection)) {
                _in = null;
                _out = null;
                // do NOT close the socket itself, since the message body has not yet been read!
            } else {
                connection = _response.getHeader("Connection");
                String version = request.getVersion();
                if (version.equals("HTTP/1.0") && "Keep-alive".equalsIgnoreCase(connection)) {
                    _lastRequestTime = System.currentTimeMillis();
                } else if (version.equals("HTTP/1.1") && (connection == null || !connection.equalsIgnoreCase("Close"))) {
                    _lastRequestTime = System.currentTimeMillis();
                } else {
                    _logger.info("Closing connection!");
                    _in = null;
                    _out = null;
                    // do NOT close the socket itself, since the message body has not yet been read!
                }
            }
            tries ++;
        } while (tries < 3 && ((status.equals("401") && authHeader != null) || (status.equals("407") && proxyAuthHeader != null)));
        
        if (_authCreds != null)
            request.setHeader("Authorization", _authCreds);
        // There is not really a good reason to keep this header
        request.deleteHeader("Proxy-Authorization");
        if (_keyFingerprint != null)
            request.setHeader("X-SSLClientCertificate", _keyFingerprint);
        
        return _response;
    }
    
    private void connect(HttpUrl url) throws IOException {
        if (! invalidSocket(url)) return;
        _logger.fine("Opening a new connection");
        _socket = new Socket();
        _socket.setSoTimeout(_timeout);
        _direct = true;
        
        // We record where we are connected to, in case we might reuse this socket later
        _host = url.getHost();
        _port = url.getPort();
        boolean ssl = url.getScheme().equalsIgnoreCase("https");
        
        if (useProxy(url)) {
            if (!ssl) {
                _logger.fine("Connect to " + _httpProxy + ":" + _httpProxyPort);
                _socket.connect(new InetSocketAddress(_httpProxy, _httpProxyPort), _connectTimeout);
                _in = _socket.getInputStream();
                _out = _socket.getOutputStream();
                _direct = false;
            } else {
                _socket.connect(new InetSocketAddress(_httpsProxy, _httpsProxyPort), _connectTimeout);
                _in = _socket.getInputStream();
                _out = _socket.getOutputStream();
                String oldAuthHeader = null;
                String authHeader = constructAuthenticationHeader(null, _proxyAuthCreds);
                String status;
                do {
                    _out.write(("CONNECT " + _host + ":" + _port + " HTTP/1.0\r\n").getBytes());
                    if (authHeader != null) {
                        _out.write(("Proxy-Authorization: " + authHeader + "\r\n").getBytes());
                    }
                    _out.write("\r\n".getBytes());
                    _out.flush();
                    _logger.fine("Sent CONNECT, reading Proxy response");
                    Response response = new Response();
                    response.read(_in);
                    _logger.fine("Got proxy response " + response.getStatusLine());
                    status = response.getStatus();
                    if (status.equals("407")) {
                        response.flushContentStream();
                        oldAuthHeader = authHeader;
                        String[] challenges = response.getHeaders("Proxy-Authenticate");
                        if (_proxyAuthCreds == null && _authenticator != null)
                            _proxyAuthCreds = _authenticator.getProxyCredentials(_httpsProxy, challenges);
                        if (_proxyAuthCreds == null) {
                            _response = response;
                            return;
                        }
                        authHeader = constructAuthenticationHeader(challenges, _proxyAuthCreds);
                        if (authHeader == null || oldAuthHeader != null && oldAuthHeader.equals(authHeader)) {
                            _response = response;
                            return;
                        }
                    }
                } while (status.equals("407") && authHeader != null);
                _logger.fine("HTTPS CONNECT successful");
            }
        } else {
            _logger.fine("Connect to " + _host + ":" + _port );
            _socket.connect(new InetSocketAddress(_host, _port), _connectTimeout);
        }
        
        if (ssl) {
            // if no fingerprint is specified, get the default one
            if (_keyFingerprint == null) 
                _keyFingerprint = _sslContextManager.getDefaultKey();
            _logger.fine("Key fingerprint is " + _keyFingerprint);
            // get the associated context manager
            SSLContext sslContext = _sslContextManager.getSSLContext(_keyFingerprint);
            if (sslContext == null)
                throw new IOException("No SSL cert found matching fingerprint: " + _keyFingerprint);
            // Use the factory to create a secure socket connected to the
            // HTTPS port of the specified web server.
            try {
                SSLSocketFactory factory = (SSLSocketFactory) sslContext.getSocketFactory();
                SSLSocket sslsocket=(SSLSocket)factory.createSocket(_socket,_socket.getInetAddress().getHostName(),_socket.getPort(),true);
                sslsocket.setUseClientMode(true);
                _socket = sslsocket;
                _socket.setSoTimeout(_timeout);
            } catch (IOException ioe) {
                _logger.severe("Error layering SSL over the existing socket: " + ioe);
                throw ioe;
            }
            _logger.fine("Finished negotiating SSL");
        }
        _in = _socket.getInputStream();
        _out = _socket.getOutputStream();
    }
    
    private boolean useProxy(HttpUrl url) {
        String host = url.getHost();
        boolean ssl = url.getScheme().equalsIgnoreCase("https");
        
        if (ssl && "".equals(_httpsProxy)) {
            return false;
        } else if (!ssl && "".equals(_httpProxy)) {
            return false;
        } else {
            for (int i=0; i<_noProxy.length; i++) {
                if (_noProxy[i].startsWith(".") && host.endsWith(_noProxy[i])) {
                    return false;
                } else if (_noProxy[i].equals("<local>") && host.indexOf('.') < 0) {
                    return false;
                } else if (host.equals(_noProxy[i])) {
                    return false;
                } else {
                    try {
                        if (host.matches(Glob.globToRE(_noProxy[i]))) return false;
                    } catch (Exception e) {
                        // fail silently
                    }
                }
            }
        }
        return true;
    }
    
    private boolean invalidSocket(HttpUrl url) {
        if (_host == null || _in == null) return true; // _out may be null if we are testing
        // the right host
        if (url.getHost().equals(_host)) {
            int urlport = url.getPort();
            // and the right port
            if (urlport == _port) {
                // in the last 1 second, it could still be valid
                long now = System.currentTimeMillis();
                if (now - _lastRequestTime > 1000) {
                    _logger.fine("Socket has expired (" + (now - _lastRequestTime) + "), open a new one!");
                    return true;
                } else if (_socket.isOutputShutdown() || _socket.isClosed()) {
                    _logger.fine("Existing socket is closed");
                    return true;
                } else {
                    _logger.fine("Existing socket is valid, reusing it!");
                    return false;
                }
            } else {
                _logger.fine("Previous request was to a different port");
            }
        } else {
            _logger.fine("Previous request was to a different host");
        }
        return true;
    }
    
    private String constructAuthenticationHeader(String[] challenges, String credentials) {
        /* credentials string looks like:
         * Basic BASE64(username:password)
         * or
         * NTLM BASE64(domain\ username:password)
         */
        // _logger.info("Constructing auth header from " + credentials);
        if (credentials == null)
            return null;
        if (credentials.startsWith("Basic")) {
            return credentials;
        }
        if (challenges != null) {
            for (int i=0; i<challenges.length; i++) {
                _logger.fine("Challenge: " + challenges[i]);
                if (challenges[i].startsWith("NTLM") && credentials.startsWith("NTLM")) {
                    return attemptNegotiation(challenges[i], credentials);
                }
                if (challenges[i].startsWith("Negotiate") && credentials.startsWith("Negotiate")) {
                    _logger.fine("Attempting 'Negotiate' Authentication");
                    return attemptNegotiation(challenges[i], credentials);
                }
                _logger.info("Can't do auth for " + challenges[i]);
            }
        }
        return null;
    }
    
    private String attemptNegotiation(String challenge, String credentials) {
        String authProperty = null;
        String authMethod = null;
        String authorization = null;
        if (challenge.startsWith("NTLM")) {
            if (challenge.length() == 4) {
                authMethod = "NTLM";
            }
            if (challenge.indexOf(' ') == 4) {
                authMethod = "NTLM";
                authorization = challenge.substring(5).trim();
            }
        } else if (challenge.startsWith("Negotiate")) {
            if (challenge.length() == 9) {
                authMethod = "Negotiate";
            }
            if (challenge.indexOf(' ') == 9) {
                authMethod = "Negotiate";
                authorization = challenge.substring(10).trim();
            }
        }
        if (authMethod == null) return null;
        NtlmMessage message = null;
        if (authorization != null) {
            try {
                message = new Type2Message(Base64.decode(authorization));
            } catch (IOException ioe) {
                ioe.printStackTrace();
                return null;
            }
        }
        // reconnect();
        if (message == null) {
            message = new Type1Message();
        } else {
            credentials = credentials.substring(authMethod.length()+1); // strip off the "NTLM " or "Negotiate "
            credentials = new String(Base64.decode(credentials)); // decode the base64
            String domain = credentials.substring(0, credentials.indexOf("\\"));
            String user = credentials.substring(domain.length()+1, credentials.indexOf(":"));
            String password = credentials.substring(domain.length()+user.length()+2);
            _logger.fine("Domain : '" + domain + "' username : '" + user + "' password length : " + password.length());
            Type2Message type2 = (Type2Message) message;
            message = new Type3Message(type2, password, domain, user, Type3Message.getDefaultWorkstation());
        }
        return authMethod + " " + Base64.encode(message.toByteArray());
    }
    
    private static class SocketWatcher {
        
        private Map sockets = new HashMap();
        
        public SocketWatcher() {}
        
        public synchronized void add(Socket socket) {
            Iterator it = sockets.keySet().iterator();
            while (it.hasNext()) {
                Socket sock = (Socket) it.next();
                Thread thread = (Thread) sockets.get(sock);
                if (!thread.isAlive() && sock.isConnected()) {
                    try {
                        sock.close();
                    } catch (Exception e) {}
                    it.remove();
                }
            }
            sockets.put(socket, Thread.currentThread());
        }
        
    }
    
}
