package org.owasp.webscarab.plugin.proxy;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.net.Socket;
import java.net.SocketException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import java.security.KeyStore;
import java.util.logging.Logger;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

public class ConnectionHandler implements Runnable {
    
    private static SSLSocketFactory _factory = null;
    
    private static String _keystore = "/server.p12";
    private static char[] _keystorepass = "password".toCharArray();
    private static char[] _keypassword = "password".toCharArray();
    
    static {
        KeyStore ks = null;
        KeyManagerFactory kmf = null;
        SSLContext sslcontext = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(ClassLoader.getSystemResourceAsStream(_keystore), _keystorepass);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, _keypassword);
            sslcontext = SSLContext.getInstance("SSLv3");
            sslcontext.init(kmf.getKeyManagers(), null, null);
            _factory = sslcontext.getSocketFactory();
        } catch (Exception e) {
            Logger logger = Logger.getLogger("org.owasp.webscarab.plugin.proxy.ConnectionHandler");
            logger.severe("Exception accessing keystore: " + e);
            _factory = null;
        }
    }
    
    private ProxyPlugin[] _plugins = null;
    private Listener _listener;
    private Socket _sock = null;
    private HttpUrl _base;
    private NetworkSimulator _simulator;
    
    private HTTPClient _httpClient = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private InputStream _clientIn = null;
    private OutputStream _clientOut = null;
    private InputStream _serverIn = null;
    private OutputStream _serverOut = null;
    
    public ConnectionHandler(Listener listener, Socket sock, HttpUrl base, NetworkSimulator simulator, boolean usePlugins) {
        _sock = sock;
        _listener = listener;
        _base = base;
        _simulator = simulator;
        if (usePlugins) {
            _plugins = _listener.getPlugins();
        }
        try {
            _sock.setTcpNoDelay(true);
            _sock.setSoTimeout(30 * 1000);
        } catch (SocketException se) {
            _logger.warning("Error setting socket parameters");
        }
    }
    
    public void run() {
        try {
            _clientIn = _sock.getInputStream();
            _clientOut = _sock.getOutputStream();
            if (_simulator != null) {
                _clientIn = _simulator.wrapInputStream(_clientIn);
                _clientOut = _simulator.wrapOutputStream(_clientOut);
            }
        } catch (IOException ioe) {
            _logger.severe("Error getting socket input and output streams! " + ioe);
            return;
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
            // one from the SSL socket later
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
                    _base = request.getURL();
                    proxyAuth = request.getHeader("Proxy-Authorization");
                    request = null;
                }
            }
            // if we are servicing a CONNECT, or operating as a reverse
            // proxy with an https:// base URL, negotiate SSL
            if (_base != null) {
                // we check isConnected for UnitTest purposes
                // We provide a fake socket, but can't negotiate SSL on it!
                if (_base.getScheme().equals("https") && _sock.isConnected() ) {
                    _logger.fine("Intercepting SSL connection!");
                    _sock = negotiateSSL(_sock);
                    _clientIn = _sock.getInputStream();
                    _clientOut = _sock.getOutputStream();
                    if (_simulator != null) {
                        _clientIn = _simulator.wrapInputStream(_clientIn);
                        _clientOut = _simulator.wrapOutputStream(_clientOut);
                    }
                }
            }
            
            if (_httpClient == null) _httpClient = HTTPClientFactory.getInstance().getHTTPClient();
            
            HTTPClient hc = _httpClient;
            
            // Maybe set SSL ProxyAuthorization here at a connection level?
            // I prefer it in the Request itself, since it gets archived, and
            // can be replayed trivially using netcat
            
            // layer the proxy plugins onto the recorder. We do this
            // in reverse order so that they operate intuitively
            // the first plugin in the array gets the first chance to modify
            // the request, and the last chance to modify the response
            if (_plugins != null) {
                for (int i=_plugins.length-1; i>=0; i--) {
                    hc = _plugins[i].getProxyPlugin(hc);
                }
            }
            
            // do we add an X-Forwarded-For header?
            String from = _sock.getInetAddress().getHostAddress();
            if (from.equals("127.0.0.1")) from = null;
            
            // do we keep-alive?
            String connection = null;
            String version = null;
            
            ConversationID id = null;
            do {
                // if we are reading the first from a reverse proxy, or the
                // continuation of a CONNECT from a normal proxy
                // read the request, otherwise we already have it.
                if (request == null) {
                    request = new Request();
                    _logger.fine("Reading request from the browser");
                    request.read(_clientIn, _base);
                    if (request.getMethod() == null) {
                        return;
                    }
                    if (proxyAuth != null) {
                        request.addHeader("Proxy-Authorization",proxyAuth);
                    }
                }
                if (from != null) {
                    request.addHeader("X-Forwarded-For", from);
                }
                _logger.fine("Browser requested : " + request.getMethod() + " " + request.getURL().toString());
                
                id = _listener.gotRequest(request);
                
                // pass the request through the plugins, and return the response
                Response response = null;
                try {
                    response = hc.fetchResponse(request);
                    if (response.getRequest() != null) request = response.getRequest();
                } catch (IOException ioe) {
                    _logger.severe("IOException retrieving the response for " + request.getURL() + " : " + ioe);
                    response = errorResponse(request, "IOException retrieving the response: " + ioe);
                    // prevent the conversation from being submitted/recorded
                    _listener.failedResponse(id, ioe.toString());
                    _listener = null;
                }
                if (response == null) {
                    _logger.severe("Got a null response from the fetcher");
                    return;
                }
                _logger.fine("Response : " + response.getStatusLine());
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
                if (_listener != null && request != null && !request.getMethod().equals("CONNECT")) {
                    _listener.gotResponse(id, request, response);
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
        SSLSocket sslsock;
        try {
            sslsock=(SSLSocket)_factory.createSocket(sock,sock.getInetAddress().getHostName(),sock.getPort(),true);
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
    
}
