package org.owasp.webscarab.plugin.proxy;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.logging.Logger;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.httpclient.FixedLengthInputStream;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.CookieJar;

import org.owasp.webscarab.httpclient.URLFetcher;

import org.owasp.webscarab.util.LogInputStream;
import org.owasp.webscarab.util.LogOutputStream;

public class ConnectionHandler implements Runnable {
    
    private Plug _plug;
    private ProxyPlugin[] _plugins;
    private Socket _sock = null;
    private String _base;
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private InputStream _clientIn = null;
    private OutputStream _clientOut = null;
    private InputStream _serverIn = null;
    private OutputStream _serverOut = null;
    
    private URLFetcher _uf = null;
    private ParallelFetcher _pf = null;
    
    String keystore = "/server.p12";
    char keystorepass[] = "password".toCharArray();
    char keypassword[] = "password".toCharArray();
    
    public ConnectionHandler(Socket sock, Plug plug, String base, ArrayList plugins) {
        _sock = sock;
        _plug = plug;
        _base = base;
        if (plugins == null) {
            _plugins = new ProxyPlugin[0];
        } else {
            _plugins = new ProxyPlugin[plugins.size()];
            for (int i=0; i<plugins.size(); i++) {
                _plugins[i] = (ProxyPlugin) plugins.get(i);
            }
        }
        try {
            _sock.setTcpNoDelay(true);
            _sock.setSoTimeout(30 * 1000);
        } catch (SocketException se) {
            _logger.warning("Error setting socket parameters");
        }
        
        // try {
        //     PipedInputStream scis = new PipedInputStream();
        //     PipedOutputStream scos = new PipedOutputStream(scis);
        //     // main (live) URLFetcher, writes a copy of what it reads from the server to scos
        //     _uf = new URLFetcher(null, scos);
        //     // copy URLFetcher, parses the response from scis, for submission to the model
        //     _pf = new ParallelFetcher(scis);
        // } catch (IOException ioe) {
        //     _logger.severe("IOException creating the piped streams! " + ioe);
            _logger.info("Recorded conversations will include any changes to the response by the plugins!");
            _uf = new URLFetcher();
        // }
    }
    
    public ConnectionHandler(Plug plug, InputStream clientIn, InputStream serverIn) {
        _sock = null;
        _plugins = new ProxyPlugin[0];
        _plug = plug;
        _clientIn = clientIn;
        _serverIn = serverIn;
        _uf = new URLFetcher(serverIn);
    }
    
    /*
    public ConnectionHandler(InputStream cis, OutputStream cos, InputStream sis, OutputStream sos) {
        _plugins = new ProxyPlugin[0];
        _clientIn = cis;
        _clientOut = cos;
        _serverIn = sis;
        _serverOut = sos;
        _uf = new URLFetcher(sos, sis);
    }
     */
    
    public void run() {
        if (_sock != null) {
            try {
                _clientIn = _sock.getInputStream();
                _clientOut = _sock.getOutputStream();
            } catch (IOException ioe) {
                _logger.severe("Error getting socket input and output streams! " + ioe);
                return;
            }
        }
        try {
            Request request = null;
            // if we do not already have a base URL (i.e. we operate as a normal 
            // proxy rather than a reverse proxy), check for a CONNECT
            if (_base == null) {
                try {
                    request = new Request();
                    request.read(_clientIn);
                } catch (IOException ioe) {
                    _logger.severe("Error reading the initial request" + ioe);
                    return;
                }
            }
            // if we are a normal proxy (because request is not null)
            // and the request is a CONNECT, get the base URL from the request
            // and send the OK back. We set request to null so we read a new
            // one from the SSL socket
            // If it exists, we pull the ProxyAuthorization header from the CONNECT
            // so that we can use it upstream.
            String proxyAuth = null;
            if (request != null) {
                String method = request.getMethod();
                if (method == null) {
                    return;
                } else if (method.equals("CONNECT")) {
                    if (_clientOut != null) {
                        try {
                            _clientOut.write(("HTTP/1.0 200 Ok\r\n\r\n").getBytes());
                            _clientOut.flush();
                        } catch (IOException ioe) {
                            _logger.severe("IOException writing the CONNECT OK Response to the browser " + ioe);
                            return;
                        }
                    }
                    _base = request.getURL().toString();
                    proxyAuth = request.getHeader("Proxy-Authorization");
                    request = null;
                }
            }
            // if we are servicing a CONNECT, or operating as a reverse
            // proxy with an https:// base URL, negotiate SSL
            if (_base != null) {
                if (_base.startsWith("https://") && _sock != null) {
                    _logger.fine("Intercepting SSL connection!");
                    _sock = negotiateSSL(_sock);
                    _clientIn = _sock.getInputStream();
                    _clientOut = _sock.getOutputStream();
                }
                // make sure that the base does not end with a "/"
                while (_base.endsWith("/")) {
                    _base = _base.substring(0,_base.length()-1);
                }
            }
            
            HTTPClient hc = _uf;
            
            // Maybe set SSL ProxyAuthorization here at a connection level?
            // I prefer it in the Request itself, since it gets archived, and
            // can be replayed trivially using netcat
            
            // layer the proxy plugins onto the recorder. We do this
            // in reverse order so that they operate intuitively
            // the first plugin in the array gets the first chance to modify
            // the request, and the last chance to modify the response
            for (int i=_plugins.length-1; i>=0; i--) {
                hc = _plugins[i].getProxyPlugin(hc);
            }
            
            // do we keep-alive?
            String connection = null;
            String version = null;
            do {
                // if we are reading the first from a reverse proxy, or the
                // continuation of a CONNECT from a normal proxy
                // read the request, otherwise we already have it.
                if (request == null) {
                    request = new Request();
                    if (_base != null) request.setBaseURL(_base);
                    _logger.fine("Reading request from the browser");
                    request.read(_clientIn);
                    if (request.getMethod() == null) {
                        return;
                    }
                    if (proxyAuth != null) {
                        request.addHeader("Proxy-Authorization",proxyAuth);
                    }
                }
                
                _logger.info("Browser requested : " + request.getMethod() + " " + request.getURL().toString());
                
                // start a thread reading the copy of the server's response
                if (_pf != null) {
                    _pf.readResponse(request);
                    _logger.fine("Started the parallel fetch");
                }
                // pass the request through the plugins, and return the response
                Response response = null;
                try {
                    response = hc.fetchResponse(request);
                } catch (IOException ioe) {
                    _logger.severe("IOException retrieving the response for " + request.getURL() + " : " + ioe);
                    response = errorResponse(request, "IOException retrieving the response: " + ioe);
                    // prevent the conversation from being submitted/recorded
                    _pf = null;
                    _plug = null;
                }
                if (response == null) {
                    _logger.severe("Got a null response from the fetcher");
                    return;
                }
                _logger.info("Response : " + response.getStatusLine());
                try { 
                    if (_clientOut != null) {
                        _logger.fine("Writing the response to the browser");
                        response.write(_clientOut);
                        _logger.fine("Finished writing the response to the browser");
                    }
                } catch (IOException ioe) {
                    _logger.severe("Error writing back to the browser : " + ioe);
                } finally {
                    response.flushContentStream(); // this simply flushes the content from the server
                }
                // Now we read the response from the copy of the server input stream
                // so that we avoid any possible changes made by the proxy plugins
                // if there is an error, we submit the possibly modified response
                // to the model
                if (_pf != null) {
                    Response resp = _pf.getResponse();
                    if (resp != null) { 
                        response = resp;
                    } else {
                        _logger.severe("Submitting the original, (possibly) modified response to the server");
                    }
                }
                if (_plug != null && request != null && !request.getMethod().equals("CONNECT") && response != null) {
                    _plug.addConversation("Proxy", request, response);
                }
                
                connection = response.getHeader("Connection");
                version = response.getVersion();
                
                request = null;
                
                _logger.fine("Version: " + version + " Connection: " + connection);
            } while ((version.equals("HTTP/1.0") && "keep-alive".equalsIgnoreCase(connection)) || 
                     (version.equals("HTTP/1.1") && !"close".equalsIgnoreCase(connection)));
            _logger.fine("Finished handling connection");
        } catch (Exception e) {
            _logger.severe("ConnectionHandler got an error : " + e);
            e.printStackTrace();
        } finally {
            try {
                if (_clientIn != null) _clientIn.close();
                if (_clientOut != null) _clientOut.close();
                if (_sock != null) _sock.close();
            } catch (IOException ioe) {
                _logger.warning("Error closing client socket : " + ioe);
            }
        }
    }
    
    private Socket negotiateSSL(Socket sock) throws Exception {
        KeyStore ks = null;
        KeyManagerFactory kmf = null;
        SSLContext sslcontext = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(this.getClass().getResourceAsStream(keystore), keystorepass);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keypassword);
            sslcontext = SSLContext.getInstance("SSLv3");
            sslcontext.init(kmf.getKeyManagers(), null, null);
        } catch (Exception e) {
            _logger.severe("Exception accessing keystore: " + e);
            throw e;
        }
        SSLSocketFactory factory = sslcontext.getSocketFactory();
        SSLSocket sslsock;

        try {
            sslsock=(SSLSocket)factory.createSocket(sock,sock.getInetAddress().getHostName(),sock.getPort(),true);
            sslsock.setUseClientMode(false);
            
            _logger.fine("Finished negotiating SSL - algorithm is " + sslsock.getSession().getCipherSuite());
            
            return sslsock;
        } catch (Exception e) {
            _logger.severe("Error layering SSL over the socket");
            throw e;
        }
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
    
    private class ParallelFetcher implements Runnable {
        
        private URLFetcher _puf = null;
        Thread t = null;
        private Request _request = null;
        private Response _response = null;
        
        public ParallelFetcher(InputStream is) {
            _puf = new URLFetcher(is);
        }
        
        public void run() {
            try {
                _response = _puf.fetchResponse(_request);
                _logger.fine("Got the response");
                _response.flushContentStream();
                _logger.fine("Flushed the contentStream");
                synchronized(this) {
                    this.notify();
                }
            } catch (IOException ioe) {
                _logger.severe("IOException: " + ioe);
                _response = null;
            }
        }
        
        public void readResponse(Request request) {
            if (t == null || ! t.isAlive()) {
                _request = request;
                t = new Thread(this, "ParallelFetcher");
                t.start();
            } else {
                _logger.severe("still reading previous response!");
            }
        }
        
        public Response getResponse() {
            if (t == null) {
                return null;
            } else {
                try {
                    if (t.isAlive()) {
                        synchronized(this) {
                            this.wait(250);
                        }
                    }
                    int count = 0;
                    while(t.isAlive() && count++ < 5) {
                        synchronized(this) {
                            this.wait(20000);
                        }
                        _logger.fine("Sleeping while the thread reads the response");
                    }
                } catch (InterruptedException ie) {}
            }
            if (t.isAlive()) {
                return null;
            } else {
                return _response;
            }
        }

    }

}
