package org.owasp.webscarab.plugin.proxy;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.util.logging.Logger;

import org.owasp.webscarab.httpclient.HTTPClient;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.httpclient.URLFetcher;

public class ConnectionHandler implements Runnable {
    
/*-----------------------------------------------------------------------+
|  PRIVATE PART                                                          |
+-----------------------------------------------------------------------*/
    
    private Request _request;
    private URL _base = null;
    
    private Logger logger = Logger.getLogger("Plug.Proxy");
    private Plug _plug;
    private ProxyPlugin[] _plugins;
    private Socket _sock;
    private InputStream clientin;
    private OutputStream clientout;
    
    private boolean isSSL = false;
    
    private Thread thread;
    
    private String sslDestination;
    private String sslServer = "";
    private int sslPort = 0;
    
    String keystore = "/serverkeys";
    char keystorepass[] = "password".toCharArray();
    char keypassword[] = "password".toCharArray();
        
/*-----------------------------------------------------------------------+
|  PUBLIC INTERFACE                                                      |
+-----------------------------------------------------------------------*/
    public ConnectionHandler(Socket sock, Plug plug, URL base, ProxyPlugin[] plugins) {
        _sock = sock;
        _plug = plug;
        _base = base;
        _plugins = plugins;
        
        try {
            sock.setTcpNoDelay(true);
            sock.setSoTimeout(5 * 60 * 1000);
        } catch (SocketException se) {
            logger.warning("Error setting socket parameters");
        }
        try {
            clientin = _sock.getInputStream();
            clientout = _sock.getOutputStream();
        } catch (IOException ioe) {
            logger.severe("Error getting socket input and output streams! " + ioe);
            return;
        }
        thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }
    
    /* Runnable *********************************************************/
    
    public void run() {
        try {
            // if we do not already have a base URL (i.e. we operate as a normal 
            // proxy rather than a reverse proxy), check for a CONNECT
            if (_base == null) {
                try {
                    _request = new Request();
                    _request.read(clientin);
                } catch (IOException ioe) {
                    logger.severe("Error reading the initial request" + ioe);
                    throw ioe;
                }
            }
            // if we are a normal proxy (because _request is not null)
            // and the request is a CONNECT, get the base URL from the request
            // and send the OK back. We set _request to null so we read a new
            // one from the SSL socket
            // If it exists, we pull the ProxyAuthorization header from the CONNECT
            // so that we can use it upstream.
            String proxyAuth = null;
            if (_request != null && _request.getMethod().equals("CONNECT")) {
                try {
                    clientout.write(("HTTP/1.0 200 Ok\r\n\r\n").getBytes());
                    clientout.flush();
                } catch (IOException ioe) {
                    logger.severe("IOException writing the CONNECT OK Response to the browser " + ioe);
                    throw ioe;
                }
                _base = _request.getURL();
                proxyAuth = _request.getHeader("Proxy-Authorization");
                _request = null;
            }
            // if we are servicing a CONNECT, or operating as a reverse
            // proxy with an https:// base URL, negotiate SSL
            if (_base != null && _base.toString().startsWith("https://")) {
                logger.info("Intercepting SSL connection!");
                negotiateSSL();
            }
            
            // beats me why netbeans complains about this following line
            // URLFetcher implements HTTPClient!
            HTTPClient hc = new URLFetcher();
            // Maybe set SSL ProxyAuthorization here at a connection level?
            // I prefer it in the Request itself, since it gets archived, and
            // can be replayed trivially using netcat
            
            // ConversationRecorder keeps a copy of the conversation
            // that flows through it. We need this to support
            // stream based transmission of responses through the
            // proxy, while still being able to send a copy of the
            // conversation to the model
            ConversationRecorder recorder = new ConversationRecorder(hc);
            hc = recorder;
            
            // layer the proxy plugins onto the recorder. We do this
            // in reverse order so that they operate intuitively
            // the first plugin in the array gets the first chance to modify
            // the request, and the last chance to modify the response
            for (int i=_plugins.length-1; i>=0; i--) {
                hc = _plugins[i].getProxyPlugin(hc);
            }
            
            // do we keep-alive?
            String connection = null;
            do {
                // if we are reading the first from a reverse proxy, or the
                // continuation of a CONNECT from a normal proxy
                // read the request, otherwise we already have it.
                if (_request == null) {
                    _request = new Request();
                    _request.setBaseURL(_base);
                    _request.read(clientin);
                    if (proxyAuth != null) {
                        _request.addHeader("Proxy-Authorization",proxyAuth);
                    }
                }
                logger.info("Got a request for : " + _request.getURL().toString());
                
                // pass the request through the plugins, and return the response
                Response response = hc.fetchResponse(_request);
                if (response == null) {
                    logger.severe("Got a null response from the fetcher");
                    throw new NullPointerException("response was null");
                }
                logger.info("Got a response : " + response.getStatusLine());
                response.write(clientout);
                if (_plug != null) {
                    Request req = recorder.getRequest();
                    Response resp = recorder.getResponse();
                    if (req != null && resp != null) {
                        _plug.addConversation(req, resp);
                    }
                    recorder.reset();
                }
                _request = null;
                connection = response.getHeader("Connection");
            } while (connection != null && connection.equals("Keep-Alive"));
        } catch (Exception e) {
            logger.warning("Got an error : " + e);
        } finally {
            try {
                clientin.close();
                clientout.close();
                _sock.close();
            } catch (IOException ioe2) {
                logger.warning("Error closing client socket : " + ioe2);
            }
        }            
    }
    
    // FIXME: there is a problem here, we don't negotiate an algorithm! ???
    // looks like we are not finding the server key.
    private void negotiateSSL() {
        KeyStore ks = null;
        KeyManagerFactory kmf = null;
        SSLContext sslcontext = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(this.getClass().getResourceAsStream(keystore), keystorepass);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keypassword);
            sslcontext = SSLContext.getInstance("SSLv3");
            sslcontext.init(kmf.getKeyManagers(), null, null);
        } catch (Exception e) {
            logger.severe("Exception accessing keystore: " + e);
            try {
                _sock.close();
            } catch (IOException ioe) {}
        }
        SSLSocketFactory factory = sslcontext.getSocketFactory();
        SSLSocket sslsock;

        try {
            sslsock=(SSLSocket)factory.createSocket(_sock,_sock.getInetAddress().getHostName(),_sock.getPort(),true);
            sslsock.setUseClientMode(false);
            
            logger.info("Finished negotiating SSL - algorithm is " + sslsock.getSession().getCipherSuite());
            
            _sock = sslsock;
            clientin = _sock.getInputStream();
            clientout = _sock.getOutputStream();
        } catch (IOException ioe) {
            logger.severe("Error layering SSL over the existing socket");
            try {
                _sock.close();
            } catch (IOException ioe2) {}
        }

    }
        
}
