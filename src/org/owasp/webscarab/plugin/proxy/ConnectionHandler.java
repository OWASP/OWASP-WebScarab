package org.owasp.webscarab.plugin.proxy;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.util.ArrayList;

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
    
    private static Object _lock = new Object();
    private static int _connectionCount = 1;
    private int _connection;
    public static boolean _debugRequest = false;
    public static boolean _debugResponse = false;
    private static String _tmpdir = System.getProperty("java.io.tmpdir");
    
    private Plug _plug;
    private ProxyPlugin[] _plugins;
    private Socket _sock;
    private String _base;
    
    String keystore = "/serverkeys";
    char keystorepass[] = "password".toCharArray();
    char keypassword[] = "password".toCharArray();
        
    public ConnectionHandler(Socket sock, Plug plug, String base, ArrayList plugins) {
        synchronized (_lock) {
            _connection = _connectionCount++;
        }
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
            sock.setTcpNoDelay(true);
            sock.setSoTimeout(30 * 1000);
        } catch (SocketException se) {
            System.err.println("Error setting socket parameters");
        }
        Thread thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }
    
    public void run() {
        InputStream clientin = null;
        OutputStream clientout = null;
        try {
            clientin = _sock.getInputStream();
            clientout = _sock.getOutputStream();
            if (_debugRequest) {
            // take a byte for byte copy of what we see on the InputStream
                PrintStream debug = new PrintStream(new FileOutputStream(_tmpdir+"/fromclient-"+_connection));
                clientin = new LogInputStream(clientin, debug);
            }
            if (_debugResponse) {
                PrintStream debug = new PrintStream(new FileOutputStream(_tmpdir+"/toclient-"+_connection));
                clientout = new LogOutputStream(clientout, debug);
            }                
        } catch (IOException ioe) {
            System.err.println("Error getting socket input and output streams! " + ioe);
            return;
        }
        try {
            Request request = null;
            // if we do not already have a base URL (i.e. we operate as a normal 
            // proxy rather than a reverse proxy), check for a CONNECT
            if (_base == null) {
                try {
                    request = new Request();
                    request.read(clientin);
                } catch (IOException ioe) {
                    System.err.println("Error reading the initial request" + ioe);
                    throw ioe;
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
                    try {
                        clientout.write(("HTTP/1.0 200 Ok\r\n\r\n").getBytes());
                        clientout.flush();
                    } catch (IOException ioe) {
                        System.err.println("IOException writing the CONNECT OK Response to the browser " + ioe);
                        throw ioe;
                    }
                    _base = request.getURL().toString();
                    proxyAuth = request.getHeader("Proxy-Authorization");
                    request = null;
                }
            }
            // if we are servicing a CONNECT, or operating as a reverse
            // proxy with an https:// base URL, negotiate SSL
            if (_base != null) {
                if (_base.startsWith("https://")) {
                    System.err.println("Intercepting SSL connection!");
                    
                    _sock = negotiateSSL(_sock);
                    clientin = _sock.getInputStream();
                    clientout = _sock.getOutputStream();
                    
                    if (_debugRequest) {
                    // take a byte for byte copy of what we see on the InputStream
                        PrintStream debug = new PrintStream(new FileOutputStream(_tmpdir+"/fromclient-"+_connection+"-ssl"));
                        clientin = new LogInputStream(clientin, debug);
                    }
                    if (_debugResponse) {
                    // take a byte for byte copy of what we send to the OutputStream
                        PrintStream debug = new PrintStream(new FileOutputStream(_tmpdir+"/toclient-"+_connection+"-ssl"));
                        clientout = new LogOutputStream(clientout, debug);
                    }
                }
                // make sure that the base does not end with a "/"
                while (_base.endsWith("/")) {
                    _base = _base.substring(0,_base.length()-1);
                }
            }
            
            // URLFetcher implements HTTPClient!
            URLFetcher uf = new URLFetcher();
            PrintStream serverRequest = null;
            PrintStream serverResponse = null;
            if (_debugRequest) {
                serverRequest = new PrintStream(new FileOutputStream(_tmpdir+"/toserver-"+_connection));
            }
            if (_debugResponse) {
                serverResponse = new PrintStream(new FileOutputStream(_tmpdir+"/fromserver-"+_connection));
            }
            uf.setDebug(serverRequest, serverResponse);
            HTTPClient hc = uf;
            
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
                if (request == null) {
                    request = new Request();
                    request.setBaseURL(_base);
                    request.read(clientin);
                    if (request.getMethod() == null) {
                        return;
                    }
                    if (proxyAuth != null) {
                        request.addHeader("Proxy-Authorization",proxyAuth);
                    }
                }
                String cl = request.getHeader("Content-Length");
                InputStream cs = request.getContentStream();
                if (cs != null && cl != null) {
                    try {
                        int length = Integer.parseInt(cl);
                        request.setContentStream(new FixedLengthInputStream(cs, length));
                    } catch (NumberFormatException nfe) {
                        System.err.println("Error parsing ContentLength");
                        throw nfe;
                    }
                }
                System.out.println("Requested : " + request.getMethod() + " " + request.getURL().toString());
                
                // pass the request through the plugins, and return the response
                Response response = hc.fetchResponse(request);
                if (response == null) {
                    System.err.println("Got a null response from the fetcher");
                    return;
                }
                System.out.println("Response : " + response.getStatusLine());
                try {
                    response.write(clientout);
                } catch (Exception e) {
                    System.err.println("Error writing back to the browser : " + e);
                    e.printStackTrace();
                }
                if (_plug != null) {
                    Request req = recorder.getRequest();
                    Response resp = recorder.getResponse();
                    if (req != null && resp != null) {
                        _plug.addConversation(req, resp);
                    }
                    recorder.reset();
                }
                request = null;
                connection = response.getHeader("Connection");
            } while (connection != null && connection.equals("Keep-Alive"));
        } catch (Exception e) {
            System.err.println("ConnectionHandler got an error : " + e);
            e.printStackTrace();
        } finally {
            try {
                clientin.close();
                clientout.close();
                _sock.close();
            } catch (IOException ioe2) {
                System.err.println("Error closing client socket : " + ioe2);
            }
        }
    }
    
    private Socket negotiateSSL(Socket sock) throws Exception {
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
            System.err.println("Exception accessing keystore: " + e);
            throw e;
        }
        SSLSocketFactory factory = sslcontext.getSocketFactory();
        SSLSocket sslsock;

        try {
            sslsock=(SSLSocket)factory.createSocket(sock,sock.getInetAddress().getHostName(),sock.getPort(),true);
            sslsock.setUseClientMode(false);
            
            System.err.println("Finished negotiating SSL - algorithm is " + sslsock.getSession().getCipherSuite());
            
            return sslsock;
        } catch (Exception e) {
            System.err.println("Error layering SSL over the existing socket");
            throw e;
        }
    }
    
}
