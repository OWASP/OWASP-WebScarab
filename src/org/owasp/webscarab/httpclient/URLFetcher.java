/*
 * URLFetcher.java
 *
 * Created on April 12, 2003, 1:31 AM
 */

package org.owasp.webscarab.httpclient;

import java.net.URL;
import java.net.MalformedURLException;
import java.net.ConnectException;

import java.io.IOException;

import java.net.Socket;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.FileOutputStream;

import java.net.UnknownHostException;
import java.net.SocketException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
import java.security.KeyStore;

import java.util.logging.Logger;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.util.LogInputStream;
import org.owasp.webscarab.util.LogOutputStream;


/** Creates a new instance of URLFetcher
 * @author rdawes
 */
public class URLFetcher implements HTTPClient {
    
    private Logger _logger = Logger.getLogger("org.owasp.webscarab");
    
    static private String _httpProxy = "";
    static private int _httpProxyPort = 0;
    static private String _httpsProxy = "";
    static private int _httpsProxyPort = 0;
    static private String[] _noProxy = new String[0];
    
    // These represent the SSL classes required to connect to the server.
    static private SSLSocketFactory _factory = null;
    static private TrustManager[] _trustAllCerts = null;
    
    String keystore = "/client.p12";
    char keystorepass[] = "password".toCharArray();
    char keypassword[] = "password".toCharArray();
    
    private Socket _socket = null;
    private boolean _direct = false;
    private Response _response = null;
    
    // these represent an already connected socket, and the end point thereof.
    private InputStream _in = null;
    private OutputStream _out = null;
    private String _host = null;
    private int _port = 0;
    private long _lastRequestTime = 0;
    
    private boolean _debug = false;
    private boolean _quiet = false;
    
    // used to make a copy of the communication with the server
    // primarily used by the proxy, to divert a copy of what is 
    // sent between client and server, without impacting streaming performance (much?)
    private OutputStream _serverOutput = null;
    private OutputStream _serverInput = null;

    /** Creates a new instance of URLFetcher
     */
    public URLFetcher() {
    }
    
    
    /** Creates a new instance of URLFetcher, that reads its response from the 
     * supplied inputstream. This must obviously be carefully arranged, but is 
     * typically done in conjunction with a second URLFetcher that is copying
     * whatever it reads from the server to a PipedOutputStream, or previously 
     * saved it to a FileOutputStream, which is now being read from.
     * This is used for the Proxy plugin, to separate the response
     * read from the server from the (possibly modified) response that is
     * sent to the browser.
     */
    public URLFetcher(InputStream fromServer) {
        _debug = true;
        _quiet = true;
        _in = fromServer;
    }
     
    
    /** Creates a new instance of URLFetcher, that copies all data written to 
     * the server to "toServer", and copies all data read from the server to
     * "fromServer". This is used for the Proxy plugin, to separate the response
     * read from the server from the (possibly modified) response that is 
     * sent to the browser.
     */
    public URLFetcher(OutputStream toServer, OutputStream fromServer) {
        _serverOutput = toServer;
        _serverInput = fromServer;
    }
    
    /** Create and install a trust manager that does not verify server SSL certificates
     */
    
    private void initSSL() throws Exception {
        // Create a trust manager that does not validate certificate chains
        _trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };
        
        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(this.getClass().getResourceAsStream(keystore), keystorepass);
            kmf.init(ks, keypassword);
            sc.init(kmf.getKeyManagers(), _trustAllCerts, new java.security.SecureRandom());
            _factory = (SSLSocketFactory)sc.getSocketFactory();
        } catch (Exception e) {
            _logger.severe("Error setting up SSL support : " + e);
            throw e;
        }
    }
    
    /** Tells all instances of URLFetcher which HTTP proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTP requests
     * @param proxyport The port on the proxy server to connect to
     */
    synchronized static public void setHttpProxy(String proxy, int proxyport) {
        _httpProxy = proxy;
        _httpProxyPort = proxyport;
    }
    
    /** Returns the address of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The address of the HTTP proxy configured, or null if none is configured
     */
    synchronized static public String getHttpProxyServer() {
        return _httpProxy;
    }
    
    /** Returns the port of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The port of the currently configured HTTP proxy, or 0 if none is configured
     */
    synchronized static public int getHttpProxyPort() {
        return _httpProxyPort;
    }
    
    /** Tells all instances of URLFetcher which HTTPS proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTPS requests
     * @param proxyport The port on the proxy server to connect to
     */
    synchronized static public void setHttpsProxy(String proxy, int proxyport) {
        _httpsProxy = proxy;
        _httpsProxyPort = proxyport;
    }
    
    /** Returns the address of the HTTPs proxy server that all instances of URLFetcher
     * will use
     * @return The address of the HTTPs proxy configured, or null if none is configured
     */
    synchronized static public String getHttpsProxyServer() {
        return _httpsProxy;
    }
    
    /** Returns the port of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The port of the currently configured HTTP proxy, or 0 if none is configured
     */
    synchronized static public int getHttpsProxyPort() {
        return _httpsProxyPort;
    }
    
    /** Accepts a comma separated list of hostnames for which no proxy should be used.
     * if the hostname begins with a period ("."), than all hosts in that domain will
     * ignore the configured proxies
     * @param noproxy A comma separated list of hosts or domains for which no proxy should be used.
     * Domains must start with a period (".")
     */
    synchronized static public void setNoProxy(String[] noproxy) {
        _noProxy = noproxy;
    }
    
    /** returns the list of hosts and domains that bypass any configured proxies
     * @return Returns a comma separated list of hosts and domains for which no proxy should be
     * used (i.e. direct connection should be made)
     */
    synchronized static public String[] getNoProxy() {
        return _noProxy;
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
        };
        if (request == null) {
            _logger.severe("Asked to fetch a null request");
            return null;
        }
        URL url = request.getURL();
        if (url == null) {
            _logger.severe("Asked to fetch a request with a null URL");
            return null;
        }
        
        if (invalidSocket(url)) {
            String proxyAuth = request.getHeader("Proxy-Authentication");
            _socket = opensocket(url, proxyAuth);
            if (_response != null) {
                return _response;
            } else {
                if (!_debug) {
                    _in = _socket.getInputStream();
                    _out = _socket.getOutputStream();
                    if (_serverInput != null) {
                        _in = new LogInputStream(_in, new PrintStream(_serverInput, true));
                    }
                    if (_serverOutput != null) {
                        _out = new LogOutputStream(_out, new PrintStream(_serverOutput, true));
                    }
                }
            }
        }
        // Still send the real request
        if (_out != null) { // we are connected to a live server
            _logger.fine("Writing the request");
            // depending on whether we are connected directly to the server, or via a proxy
            if (_direct) {
                request.writeDirect(_out);
            } else {
                request.write(_out);
            }
            _out.flush();
            _logger.fine("Finished writing the request");
        } else {
            // we make sure that the request body has been read (if any)
            request.flushContentStream();
        }

        _response = new Response();
        _response.setRequest(request);

        // test for spurious 100 header from IIS 4 and 5. 
        // See http://mail.python.org/pipermail/python-list/2000-December/023204.html
        _logger.fine("Reading the response");
        do {
            _response.read(_in);
        } while (_response.getStatus().equals("100"));

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
                _in = null;
                _out = null;
                // do NOT close the socket itself, since the message body has not yet been read!
            }
        }
        return _response;
    }
    
    private Socket opensocket(URL url, String proxyAuth) throws IOException {
        // We initialise to null;
        Socket socket = null;
        _direct = true;
        
        // We record where we are connected to, in case we might reuse this socket later
        _host = url.getHost();
        _port = url.getPort()==-1?url.getDefaultPort():url.getPort();
        boolean ssl = url.getProtocol().equalsIgnoreCase("https");
        
        if (useProxy(url)) {
            if (!ssl) {
                _logger.fine("Connect to " + _httpProxy + ":" + _httpProxyPort);
                if (!_debug) {
                    socket = new Socket(_httpProxy, _httpProxyPort);
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(60 * 1000);
                }
                _direct = false;
                return socket;
            } else {
                // Send CONNECT, get OK, then we have a socket to the server
                // _logger.fine("Connect to " + _httpsProxy + ":" + _httpsProxyPort);
                if (!_debug) {
                    // _logger.fine("Proxy CONNECT to " + _host + ":" + _port);
                    socket = new Socket(_httpsProxy, _httpsProxyPort);
                    _in = socket.getInputStream();
                    _out = socket.getOutputStream();
                    if (_serverInput != null) {
                        _in = new LogInputStream(_in, new PrintStream(_serverInput, true));
                    }
                    if (_serverOutput != null) {
                        _out = new LogOutputStream(_out, new PrintStream(_serverOutput, true));
                    }
                }
                if (_out != null) {
                    _out.write(("CONNECT " + _host + ":" + _port + " HTTP/1.0\r\n").getBytes());
                    if (proxyAuth != null && !proxyAuth.equals("")) {
                        _out.write(("Proxy-Authorization: " + proxyAuth + "\r\n").getBytes());
                    }
                    _out.write("\r\n".getBytes());
                    _out.flush();
                    _logger.fine("Sent CONNECT, reading Proxy response");
                }
                Response response = new Response();
                response.read(_in);
                _logger.fine("Got proxy response " + response.getStatusLine());
                if (!response.getStatus().equals("200")) {
                    _response = response;
                    return null;
                }
                _logger.fine("HTTPS CONNECT successful");
            }
        } else {
            if (!_debug) {
                _logger.fine("Connect to " + _host + ":" + _port );
                socket = new Socket(_host, _port);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(60 * 1000);
            }
        }
        
        if (!_debug && ssl && socket != null) {
            if (_factory == null) {
                try {
                    initSSL();
                } catch (Exception e) {
                    throw new IOException(e.toString());
                }
            }
            // Use the factory to create a secure socket connected to the
            // HTTPS port of the specified web server.
            try {
                SSLSocket sslsocket=(SSLSocket)_factory.createSocket(socket,socket.getInetAddress().getHostName(),socket.getPort(),true);
                sslsocket.setUseClientMode(true);
                socket = sslsocket;
            } catch (IOException ioe) {
                _logger.severe("Error layering SSL over the existing socket");
                ioe.printStackTrace();
                throw new SocketException("Error layering SSL over the socket " + ioe);
            }
            _logger.fine("Finished negotiating SSL");
        }
        return socket;
    }
    
    private boolean useProxy(URL url) {
        String host = url.getHost();
        boolean ssl = url.getProtocol().equalsIgnoreCase("https");
        
        if (ssl && (_httpsProxy == null || "".equals(_httpsProxy))) {
            return false;
        } else if (!ssl && (_httpProxy == null || "".equals(_httpProxy))) {
            return false;
        } else {
            for (int i=0; i<_noProxy.length; i++) {
                if (_noProxy[i].startsWith(".") && host.endsWith(_noProxy[i])) {
                    return false;
                } else if (host.equals(_noProxy[i])) {
                    return false;
                }
            }
        }
        return true;
    }
    
    private boolean invalidSocket(URL url) {
        if (_host == null || _in == null) return true; // _out may be null if we are testing
        // the right host
        if (url.getHost().equals(_host)) {
            int urlport = url.getPort()==-1?url.getDefaultPort():url.getPort();
            // and the right port
            if (urlport == _port) {
                // in the last 1 second, it could still be valid
                long now = System.currentTimeMillis();
                if (!_debug && (now - _lastRequestTime > 1000)) {
                    _logger.fine("Socket has expired (" + (now - _lastRequestTime) + "), open a new one!");
                    return true;
                } else if (!_debug && (_socket.isOutputShutdown() || _socket.isClosed())) {
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

}
