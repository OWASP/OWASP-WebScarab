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
import java.util.logging.Logger;

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
    
    static private String httpProxy = "";
    static private int httpProxyPort = 0;
    static private String httpsProxy = "";
    static private int httpsProxyPort = 0;
    static private String noProxy = "";
    static private String[] noProxies = new String[0];
    
    // These represent the SSL classes required to connect to the server.
    static private SSLSocketFactory factory = null;
    static private TrustManager[] trustAllCerts = null;

    private Socket proxysocket = null;
    private Socket serversocket = null;
    private SSLSocket sslsocket = null;
    
    // these represent an already connected socket, and the end point thereof.
    private InputStream in = null;
    private OutputStream out = null;
    private String host = null;
    private int port = 0;
    private boolean ssl = false;
    
    private Request request = null;
    private Response response = null;
    
    private static Logger logger = Logger.getLogger("WebScarab.URLFetcher");
    
    /** Creates a new instance of URLFetcher
     */
    public URLFetcher() {
    }
    
    /** Create and install a trust manager that does not verify server SSL certificates
     */    
    
    private void initSSL() {
        // Create a trust manager that does not validate certificate chains
        trustAllCerts = new TrustManager[]{
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
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            factory = (SSLSocketFactory)sc.getSocketFactory();
        } catch (java.security.NoSuchAlgorithmException nsae) {
            logger.severe("Error setting up SSL support - No Such Algorithm Exception " + nsae);
        } catch (java.security.KeyManagementException kme) {
            logger.severe("Error setting up SSL Support - Key management exception " + kme);
        }
    }
 
    /** Tells all instances of URLFetcher which HTTP proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTP requests
     * @param proxyport The port on the proxy server to connect to
     */    
    synchronized static public void setHttpProxy(String proxy, int proxyport) {
        httpProxy = proxy;
        httpProxyPort = proxyport;
    }
    
    /** Returns the address of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The address of the HTTP proxy configured, or null if none is configured
     */    
    synchronized static public String getHttpProxyServer() {
        return httpProxy;
    }
    
    /** Returns the port of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The port of the currently configured HTTP proxy, or 0 if none is configured
     */    
    synchronized static public int getHttpProxyPort() {
        return httpProxyPort;
    }
    
    /** Tells all instances of URLFetcher which HTTPS proxy to use, if any
     * @param proxy The address or name of the proxy server to use for HTTPS requests
     * @param proxyport The port on the proxy server to connect to
     */    
    synchronized static public void setHttpsProxy(String proxy, int proxyport) {
        httpsProxy = proxy;
        httpsProxyPort = proxyport;
    }
    
    /** Returns the address of the HTTPs proxy server that all instances of URLFetcher
     * will use
     * @return The address of the HTTPs proxy configured, or null if none is configured
     */    
    synchronized static public String getHttpsProxyServer() {
        return httpsProxy;
    }
    
    /** Returns the port of the HTTP proxy server that all instances of URLFetcher
     * will use
     * @return The port of the currently configured HTTP proxy, or 0 if none is configured
     */    
    synchronized static public int getHttpsProxyPort() {
        return httpsProxyPort;
    }
    
    /** Accepts a comma separated list of hostnames for which no proxy should be used.
     * if the hostname begins with a period ("."), than all hosts in that domain will
     * ignore the configured proxies
     * @param noproxy A comma separated list of hosts or domains for which no proxy should be used.
     * Domains must start with a period (".")
     */    
    synchronized static public void setNoProxy(String noproxy) {
        noProxy = noproxy;
        if (!noproxy.equals("")) {
            noProxies = noProxy.split(" *, *");
        } else {
            noProxies = new String[0];
        }
    }
    
    /** returns the list of hosts and domains that bypass any configured proxies
     * @return Returns a comma separated list of hosts and domains for which no proxy should be
     * used (i.e. direct connection should be made)
     */    
    synchronized static public String getNoProxy() {
        return noProxy;
    }
    
    /** Can be used by a calling class to fetch a request without spawning an additional
     * thread. This is appropriate when the calling class is already running in an
     * independant thread, and must wait for the response before continuing.
     * @return the retrieved response
     * @param request the request to retrieve.
     */    
    public Response fetchResponse(Request request) {
        if (request == null) {
            logger.severe("Request is null");
            return null;
        }
        this.request = request;
 
        try {
            opensocket(request);
        } catch (UnknownHostException uhe) {
            return errorResponse(request, "Unknown host exception " + uhe);
        } catch (IOException ioe) {
            return errorResponse(request, "IOException " + ioe);
        }
        if (response != null) {
            return response;
        }
        if (out == null || in == null) {
            return errorResponse(request, "Unknown error : in or out was null!");
        }
        // Still send the real request
        try {
            // Not ideal, but likely won't affect anything too negatively
            // This could slow down large POST's a lot, since we read it all before starting to write
            // needed so that we can associate the request content with the Response later.
            if (request.getContentStream() != null) {
                request.readContentStream();
            }
            /*if (sslsocket != null) {
                request.writeDirect(out);
            } else*/ if (proxysocket != null) {
                request.write(out);
            } else if (serversocket != null) {
                request.writeDirect(out);
            }
            out.flush();
            
            response = new Response();
            response.setRequest(request); 
            response.read(in);
            String length = response.getHeader("Content-Length");
            if (length != null) {
                try {
                    int cl = Integer.parseInt(length);
                    response.setContentStream(new FixedLengthInputStream(response.getContentStream(),cl));
                } catch (NumberFormatException nfe) {
                    logger.severe("NumberFormatException parsing content length = '" + length + "'\n " + nfe);
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
            logger.info(request.getURL() +" : " + response.getStatusLine());
            return response;
        } catch (IOException ioe) {
            return errorResponse(request,"IOException " + ioe);
        }
    }
    
    private void opensocket(Request request) throws UnknownHostException, IOException, SocketException  {
        // We initialise all sockets to null;
        proxysocket = null;
        serversocket = null;
        sslsocket = null;
        response = null;
        in = null;
        out = null;
        
        // We record where we are connected to, in case we might reuse this socket later
        URL u = request.getURL();
        host = u.getHost();
        port = u.getPort()==-1?u.getDefaultPort():u.getPort();
        ssl = request.getURL().getProtocol().equalsIgnoreCase("https");
        
        if (!ssl) {
            // Check for a "noProxy" entry here
            if (httpProxy != null && !httpProxy.equals("")) {
                logger.info("Connect to " + httpProxy + ":" + httpProxyPort);
                proxysocket = new Socket(httpProxy, httpProxyPort);
                proxysocket.setTcpNoDelay(true);
                proxysocket.setSoTimeout(60 * 1000);
                in = proxysocket.getInputStream();
                out = proxysocket.getOutputStream();
            } else {
                logger.info("Connect to " + u.getHost() + ":" + port );
                serversocket = new Socket(u.getHost(), port);
                serversocket.setTcpNoDelay(true);
                serversocket.setSoTimeout(60 * 1000);
                in = serversocket.getInputStream();
                out = serversocket.getOutputStream();
            }
        } else {
            // check for a noProxy entry here
            if (httpsProxy != null && !httpsProxy.equals("")) {
                // Send CONNECT, get OK, then we have a socket to the server
                logger.info("Connect to " + httpsProxy + ":" + httpsProxyPort);
                proxysocket = new Socket(httpsProxy, httpsProxyPort);
                logger.info("Proxy CONNECT to " + u.getHost() + ":" + port);
                OutputStream proxyout = proxysocket.getOutputStream();
                InputStream proxyin = proxysocket.getInputStream();
                proxyout.write(("CONNECT " + host + ":" + port + " HTTP/1.0\r\n").getBytes());
                String proxyAuth = request.getHeader("Proxy-Authorization");
                if (proxyAuth != null && !proxyAuth.equals("")) {
                    proxyout.write(("Proxy-Authorization: " + proxyAuth + "\r\n").getBytes());
                    request.deleteHeader("Proxy-Authorization");
                }
                proxyout.write("\r\n".getBytes());
                proxyout.flush();
                logger.info("Sent CONNECT, reading Proxy response");
                response = new Response();
                response.read(proxyin);
                logger.info("Got response " + response.getStatusLine());
                if (!response.getStatus().equals("200")) {
                    return;
                }
                logger.info("HTTPS CONNECT successful");
                response = null;
                serversocket = proxysocket;
            } else {
                serversocket = new Socket(host , port);
                serversocket.setTcpNoDelay(true);
                serversocket.setSoTimeout(60 * 1000);
            }
            
            if (factory == null) {
                initSSL();
            }
            // Use the factory to create a secure socket connected to the
            // HTTPS port of the specified web server.
            try {
                sslsocket=(SSLSocket)factory.createSocket(serversocket,serversocket.getInetAddress().getHostName(),serversocket.getPort(),true);
                sslsocket.setUseClientMode(true);
                // Try comment this out to see if we reuse sessionids
                // sslsocket.startHandshake();
            } catch (IOException ioe) {
                logger.severe("Error layering SSL over the existing socket");
                throw new SocketException("Error layering SSL over the existing socket " + ioe + 
                "\nYou may want to uncomment the 'startHandshake' line above :-)");
            }
            in = sslsocket.getInputStream();
            out = sslsocket.getOutputStream();
            logger.info("Finished negotiating SSL");
        }
    }
    
    private Response errorResponse(Request request, String message) {
        Response response = new Response();
        response.setVersion("HTTP/1.0");
        response.setStatus("500");
        response.setMessage("Exodus error");
        response.setHeader("Content-Type","text/html");
        response.setHeader("Connection","Close");
        String template = "<HTML><HEAD><TITLE>Exodus Error</TITLE></HEAD>";
        template = template + "<BODY>Exodus caused an error trying to retrieve <pre>" + request.toString() + "</pre><P>";
        template = template + "The error was : <pre>" + message + "</pre><P></HTML>";
        response.setContent(template.getBytes());
        return response;
    }
    
    public boolean requestChanged() {
        return false;
    }
    
    public boolean responseChanged() {
        return false;
    }
    
    public Request getRequest() {
        return request;
    }
    
    public Response getResponse() {
        return response;
    }
        
    public static void main(String[] args) {
        try {
            Request req = new Request();
            req.setMethod("GET");
            req.setURL("http://localhost:8080/examples/jsp/num/numguess.jsp");
            req.setVersion("HTTP/1.1");
            req.setHeader("Connection","Keep-Alive");
            // req.setHeader("ETag","6684-1036786167000");
            // req.setHeader("If-Modified-Since","Fri, 08 Nov 2002 20:09:27 GMT");
            URLFetcher uf = new URLFetcher();
            Response resp = uf.fetchResponse(req);
            // System.out.println(resp.getStatusLine());
            resp.write(System.out);
            // byte[] content = resp.getContent();
            
        } catch (MalformedURLException mue) {
            System.out.println("MUE " + mue);
        } catch (IOException ioe) {
            System.out.println("IOException " + ioe);
        }
    }
}
