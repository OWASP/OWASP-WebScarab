/*
 * URLFetcher.java
 *
 * Created on April 12, 2003, 1:31 AM
 */

package org.owasp.webscarab.httpclient;

import java.net.URL;
import java.net.MalformedURLException;

import java.io.IOException;

import java.net.Socket;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;

import java.net.UnknownHostException;
import java.net.SocketException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/** Creates a new instance of URLFetcher
 * @author rdawes
 */
public class URLFetcher implements HTTPClient {
    
    static private String _httpProxy = "";
    static private int _httpProxyPort = 0;
    static private String _httpsProxy = "";
    static private int _httpsProxyPort = 0;
    static private String[] _noProxy = new String[0];
    
    // These represent the SSL classes required to connect to the server.
    static private SSLSocketFactory _factory = null;
    static private TrustManager[] _trustAllCerts = null;
    
    private Socket _proxysocket = null;
    private Socket _serversocket = null;
    private SSLSocket _sslsocket = null;
    
    // these represent an already connected socket, and the end point thereof.
    private InputStream _in = null;
    private OutputStream _out = null;
    private String _host = null;
    private int _port = 0;
    private long _lastRequestTime = 0;
    
    /** Creates a new instance of URLFetcher
     */
    public URLFetcher() {
    }
    
    /** Create and install a trust manager that does not verify server SSL certificates
     */
    
    private void initSSL() {
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
            sc.init(null, _trustAllCerts, new java.security.SecureRandom());
            _factory = (SSLSocketFactory)sc.getSocketFactory();
        } catch (java.security.NoSuchAlgorithmException nsae) {
            System.err.println("Error setting up SSL support - No Such Algorithm Exception " + nsae);
        } catch (java.security.KeyManagementException kme) {
            System.err.println("Error setting up SSL Support - Key management exception " + kme);
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
    public Response fetchResponse(Request request) {
        if (request == null) {
            System.err.println("Request is null");
            return null;
        }
        
        try {
            if (_in == null || _out == null || invalidSocket(request)) {
                Response response = opensocket(request);
                if (response != null) {
                    return response;
                }
            }
        } catch (UnknownHostException uhe) {
            return errorResponse(request, "Unknown host exception " + uhe);
        } catch (IOException ioe) {
            return errorResponse(request, "IOException " + ioe);
        }
        // Still send the real request
        try {
            // FIXME : we don't handle gzipped content properly yet. I"ve seen problems with content-length, etc
            request.deleteHeader("Accept-Encoding");
            
            // depending on whether we are connected directly to the server, or via a proxy
            if (_proxysocket != null) {
                request.write(_out);
            } else if (_serversocket != null) {
                request.writeDirect(_out);
            }
            _out.flush();
            
            Response response = new Response();
            response.setRequest(request);
            response.read(_in);
            String length = response.getHeader("Content-Length");
            if (length != null) {
                try {
                    int cl = Integer.parseInt(length);
                    response.setContentStream(new FixedLengthInputStream(response.getContentStream(),cl));
                } catch (NumberFormatException nfe) {
                    System.err.println("NumberFormatException parsing content length = '" + length + "'\n " + nfe);
                }
            }
            String chunked = response.getHeader("Transfer-Encoding");
            if (chunked != null && chunked.equalsIgnoreCase("chunked")) {
                response.setContentStream(new ChunkedInputStream(response.getContentStream()));
                response.deleteHeader("Transfer-Encoding");
                response.setHeader("X-Transfer-Encoding", chunked);
            }
            String gzipped = response.getHeader("Content-Encoding");
            if (gzipped != null && gzipped.equalsIgnoreCase("gzip")) {
                response.setContentStream(new GZIPInputStream(response.getContentStream()));
                response.deleteHeader("Content-Encoding");
                response.setHeader("X-Content-Encoding", gzipped);
            }
            System.err.println(request.getURL() +" : " + response.getStatusLine());
            
            String connection = response.getHeader("Connection");
            if (request.getVersion().equals("HTTP/1.0") && connection != null && connection.equals("Keep-Alive")) {
                System.err.println("HTTP/1.0 and connection: Keep-Alive is set");
                _lastRequestTime = System.currentTimeMillis();
            } else if (request.getVersion().equals("HTTP/1.1") && (connection == null || !connection.equals("Close"))) {
                System.err.println("HTTP/1.1 and connection: Close is not set");
                _lastRequestTime = System.currentTimeMillis();
            } else {
                _in = null;
                _out = null;
            }
            
            return response;
        } catch (IOException ioe) {
            return errorResponse(request,"IOException " + ioe);
        }
    }
    
    private Response opensocket(Request request) throws UnknownHostException, IOException, SocketException  {
        // We initialise all sockets to null;
        _proxysocket = null;
        _serversocket = null;
        _sslsocket = null;
        _in = null;
        _out = null;
        
        // We record where we are connected to, in case we might reuse this socket later
        URL u = request.getURL();
        _host = u.getHost();
        _port = u.getPort()==-1?u.getDefaultPort():u.getPort();
        boolean ssl = request.getURL().getProtocol().equalsIgnoreCase("https");
        
        if (!ssl) {
            // Check for a "noProxy" entry here
            if (_httpProxy != null && !_httpProxy.equals("")) {
                System.err.println("Connect to " + _httpProxy + ":" + _httpProxyPort);
                _proxysocket = new Socket(_httpProxy, _httpProxyPort);
                _proxysocket.setTcpNoDelay(true);
                _proxysocket.setSoTimeout(60 * 1000);
                _in = _proxysocket.getInputStream();
                _out = _proxysocket.getOutputStream();
            } else {
                System.err.println("Connect to " + _host + ":" + _port );
                _serversocket = new Socket(_host, _port);
                _serversocket.setTcpNoDelay(true);
                _serversocket.setSoTimeout(60 * 1000);
                _in = _serversocket.getInputStream();
                _out = _serversocket.getOutputStream();
            }
        } else {
            // check for a noProxy entry here
            if (_httpsProxy != null && !_httpsProxy.equals("")) {
                // Send CONNECT, get OK, then we have a socket to the server
                System.err.println("Connect to " + _httpsProxy + ":" + _httpsProxyPort);
                _proxysocket = new Socket(_httpsProxy, _httpsProxyPort);
                OutputStream proxyout = _proxysocket.getOutputStream();
                InputStream proxyin = _proxysocket.getInputStream();
                System.err.println("Proxy CONNECT to " + _host + ":" + _port);
                proxyout.write(("CONNECT " + _host + ":" + _port + " HTTP/1.0\r\n").getBytes());
                String proxyAuth = request.getHeader("Proxy-Authorization");
                if (proxyAuth != null && !proxyAuth.equals("")) {
                    proxyout.write(("Proxy-Authorization: " + proxyAuth + "\r\n").getBytes());
                    request.deleteHeader("Proxy-Authorization");
                }
                proxyout.write("\r\n".getBytes());
                proxyout.flush();
                System.err.println("Sent CONNECT, reading Proxy response");
                Response response = new Response();
                response.read(proxyin);
                System.err.println("Got response " + response.getStatusLine());
                if (!response.getStatus().equals("200")) {
                    return response;
                }
                System.err.println("HTTPS CONNECT successful");
                _serversocket = _proxysocket;
            } else {
                _serversocket = new Socket(_host , _port);
                _serversocket.setTcpNoDelay(true);
                _serversocket.setSoTimeout(60 * 1000);
            }
            
            if (_factory == null) {
                initSSL();
            }
            // Use the factory to create a secure socket connected to the
            // HTTPS port of the specified web server.
            try {
                _sslsocket=(SSLSocket)_factory.createSocket(_serversocket,_serversocket.getInetAddress().getHostName(),_serversocket.getPort(),true);
                _sslsocket.setUseClientMode(true);
            } catch (IOException ioe) {
                System.err.println("Error layering SSL over the existing socket");
                throw new SocketException("Error layering SSL over the socket " + ioe);
            }
            _in = _sslsocket.getInputStream();
            _out = _sslsocket.getOutputStream();
            System.err.println("Finished negotiating SSL");
        }
        if (_out == null || _in == null) {
            return errorResponse(request, "Unknown error : in or out was null!");
        }
        return null;
    }
    
    private Response errorResponse(Request request, String message) {
        Response response = new Response();
        response.setVersion("HTTP/1.0");
        response.setStatus("500");
        response.setMessage("WebScarab error");
        response.setHeader("Content-Type","text/html");
        response.setHeader("Connection","Close");
        String template = "<HTML><HEAD><TITLE>WebScarab Error</TITLE></HEAD>";
        template = template + "<BODY>WebScarab encountered an error trying to retrieve <P><pre>" + request.toString() + "</pre><P>";
        template = template + "The error was : <P><pre>" + message + "</pre><P></HTML>";
        response.setContent(template.getBytes());
        return response;
    }
    
    private boolean invalidSocket(Request request) {
        // the right host
        URL u = request.getURL();
        if (u.getHost().equals(_host)) {
            int urlport = u.getPort()==-1?u.getDefaultPort():u.getPort();
            // and the right port
            if (urlport == _port) {
                // in the last 1 second, it could still be valid
                if (System.currentTimeMillis() - _lastRequestTime > 1000) {
                    System.err.println("Socket has expired, open a new one!");
                    return true;
                } else {
                    System.err.println("Existing socket is valid, reusing it!");
                    return false;
                }
            } else {
                System.err.println("Previous request was to a different port");
            }
        } else {
            System.err.println("Previous request was to a different host");
        }
        return true;
    }
    
    public static void main(String[] args) {
        try {
            Request req = new Request();
            req.setMethod("GET");
            req.setURL("http://localhost:8080/examples/jsp/num/numguess.jsp");
            req.setVersion("HTTP/1.1");
            // req.setHeader("Connection","Keep-Alive");
            req.setHeader("Host","localhost:8080");
            // req.setHeader("ETag","6684-1036786167000");
            // req.setHeader("If-Modified-Since","Fri, 08 Nov 2002 20:09:27 GMT");
            URLFetcher uf = new URLFetcher();
            Response resp = uf.fetchResponse(req);
            resp.getContent();
            resp = uf.fetchResponse(req);
            resp.getContent();
        } catch (MalformedURLException mue) {
            System.out.println("MUE " + mue);
        } catch (IOException ioe) {
            System.out.println("IOException " + ioe);
        }
    }
}
