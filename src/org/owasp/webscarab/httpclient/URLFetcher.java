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
    
    String keystore = "/client.p12";
    char keystorepass[] = "password".toCharArray();
    char keypassword[] = "password".toCharArray();

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
            System.err.println("Error setting up SSL support : " + e);
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
    public Response fetchResponse(Request request) {
        if (request == null) {
            System.err.println("Request is null");
            return null;
        }
        URL url = request.getURL();
        if (url == null) {
            System.err.println("URL is null");
            return null;
        }
        
        try {
            if (_in == null || _out == null || invalidSocket(url)) {
                String proxyAuth = request.getHeader("Proxy-Authentication");
                Response response = opensocket(url, proxyAuth);
                if (response != null) {
                    return response;
                }
            }
        } catch (UnknownHostException uhe) {
            return errorResponse(request, "Unknown host exception " + uhe);
        } catch (IOException ioe) {
            // ioe.printStackTrace();
            return errorResponse(request, "IOException " + ioe);
        }
        // Still send the real request
        try {
            
            // depending on whether we are connected directly to the server, or via a proxy
            if (_proxysocket != null) {
                request.write(_out);
            } else if (_serversocket != null) {
                request.writeDirect(_out);
            }
            _out.flush();
            
            Response response = new Response();
            response.setRequest(request);

            // test for spurious 100 header from IIS 4 and 5. 
            // See http://mail.python.org/pipermail/python-list/2000-December/023204.html
            do {
                response.read(_in);
            } while (response.getStatus().equals("100"));
            
            System.err.println(request.getURL() +" : " + response.getStatusLine());
            
            String connection = response.getHeader("Proxy-Connection");
            if (connection != null && "close".equalsIgnoreCase(connection)) {
                _in = null;
                _out = null;
            } else {
                connection = response.getHeader("Connection");
                String version = request.getVersion();
                if (version.equals("HTTP/1.0") && connection != null && connection.equalsIgnoreCase("Keep-Alive")) {
                    _lastRequestTime = System.currentTimeMillis();
                } else if (version.equals("HTTP/1.1") && (connection == null || !connection.equalsIgnoreCase("Close"))) {
                    _lastRequestTime = System.currentTimeMillis();
                } else {
                    _in = null;
                    _out = null;
                }
            }
            
            return response;
        } catch (IOException ioe) {
            ioe.printStackTrace();
            return errorResponse(request,"IOException " + ioe);
        }
    }
    
    private Response opensocket(URL url, String proxyAuth) throws UnknownHostException, IOException, SocketException  {
        // We initialise all sockets to null;
        _proxysocket = null;
        _serversocket = null;
        _sslsocket = null;
        _in = null;
        _out = null;
        
        // We record where we are connected to, in case we might reuse this socket later
        _host = url.getHost();
        _port = url.getPort()==-1?url.getDefaultPort():url.getPort();
        boolean ssl = url.getProtocol().equalsIgnoreCase("https");
        
        if (useProxy(url)) {
            if (!ssl) {
                System.err.println("Connect to " + _httpProxy + ":" + _httpProxyPort);
                _proxysocket = new Socket(_httpProxy, _httpProxyPort);
                _proxysocket.setTcpNoDelay(true);
                _proxysocket.setSoTimeout(60 * 1000);
                _in = _proxysocket.getInputStream();
                _out = _proxysocket.getOutputStream();
            } else {
                // Send CONNECT, get OK, then we have a socket to the server
                System.err.println("Connect to " + _httpsProxy + ":" + _httpsProxyPort);
                _proxysocket = new Socket(_httpsProxy, _httpsProxyPort);
                OutputStream proxyout = _proxysocket.getOutputStream();
                InputStream proxyin = _proxysocket.getInputStream();
                System.err.println("Proxy CONNECT to " + _host + ":" + _port);
                proxyout.write(("CONNECT " + _host + ":" + _port + " HTTP/1.0\r\n").getBytes());
                if (proxyAuth != null && !proxyAuth.equals("")) {
                    proxyout.write(("Proxy-Authorization: " + proxyAuth + "\r\n").getBytes());
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
                _proxysocket = null;
            }
        } else {
            System.err.println("Connect to " + _host + ":" + _port );
            _serversocket = new Socket(_host, _port);
            _serversocket.setTcpNoDelay(true);
            _serversocket.setSoTimeout(60 * 1000);
            if (!ssl) {
                _in = _serversocket.getInputStream();
                _out = _serversocket.getOutputStream();
            }
        }
        
        if (ssl && _serversocket != null) {
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
                _sslsocket=(SSLSocket)_factory.createSocket(_serversocket,_serversocket.getInetAddress().getHostName(),_serversocket.getPort(),true);
                _sslsocket.setUseClientMode(true);
            } catch (IOException ioe) {
                System.err.println("Error layering SSL over the existing socket");
                ioe.printStackTrace();
                throw new SocketException("Error layering SSL over the socket " + ioe);
            }
            _in = _sslsocket.getInputStream();
            _out = _sslsocket.getOutputStream();
            System.err.println("Finished negotiating SSL");
        }
        if (_out == null || _in == null) {
            throw new IOException("no Input or OutputStream to talk to the server");
        }
        return null;
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
    
    private Response errorResponse(Request request, String message) {
        Response response = new Response();
        response.setRequest(request);
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
    
    private boolean invalidSocket(URL url) {
        // the right host
        if (url.getHost().equals(_host)) {
            int urlport = url.getPort()==-1?url.getDefaultPort():url.getPort();
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
            URLFetcher.setHttpsProxy("proxy.czprg.atrema.deloitte.com", 3128);
            Request req = new Request();
            req.setMethod("GET");
            req.setURL("https://mystic.pca.dfn.de/cgi/sslcheck.cgi");
            // req.setURL("https://localhost:4433/cgi/sslcheck.cgi");
            req.setVersion("HTTP/1.0");
            URLFetcher uf = new URLFetcher();
            Response resp = uf.fetchResponse(req);
            System.out.println(resp.toString());
        } catch (MalformedURLException mue) {
            System.out.println("MUE " + mue);
        } catch (IOException ioe) {
            System.out.println("IOException " + ioe);
        }
    }
}
