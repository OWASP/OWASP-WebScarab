package org.owasp.webscarab.plugins.proxy;

import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.util.logging.Logger;

import org.owasp.webscarab.WebScarab;
import org.owasp.webscarab.model.*;

import org.owasp.webscarab.httpclient.URLFetcher;

public class ConnectionHandler implements Runnable {
    
/*-----------------------------------------------------------------------+
|  PRIVATE PART                                                          |
+-----------------------------------------------------------------------*/
    
    private Logger logger = Logger.getLogger("WebScarab.Proxy");
    private WebScarab _webscarab;
    private ProxyPlugin[] _plugins;
    private Socket sock;
    private InputStream clientin;
    private OutputStream clientout;
    private SSLSocket sslsock;
    
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
    public ConnectionHandler(Socket sock, WebScarab webscarab, ProxyPlugin[] plugins) {
        this.sock = sock;
        _webscarab = webscarab;
        _plugins = plugins;
        
        try {
            sock.setTcpNoDelay(true);
            sock.setSoTimeout(5 * 60 * 1000);
        } catch (SocketException se) {
            logger.warning("Error setting socket parameters");
        }
        thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }
    
    /* Runnable *********************************************************/
    
    public void run() {
        try {
            String base = null;
            clientin = new BufferedInputStream(sock.getInputStream());
            clientout = sock.getOutputStream();
            logger.info("Reading request from browser");
            if (! clientin.markSupported()) {
                System.err.println("Mark not supported on sock.inputstream");
                return;
            }
            clientin.mark(4096);
            String requestLine = readLine(clientin);
            if (requestLine == null) {
                System.err.println("Null request line");
                return;
            }
            String[] parts = requestLine.split(" ");
            if (parts.length != 3) {
                System.err.println("Invalid request line: '" + requestLine + "'");
                return;
            }
            if (!parts[0].equals("CONNECT")) {
                clientin.reset();
            } else {
                System.err.println("Can't do CONNECT yet!");
                return;
                // read the rest of the CONNECT
                // negotiate SSL here
                // SSLSock sslsock = connectLocal(sock);
                // clientin = sslsock.getInputStream();
                // clientout = sslsock.getOutputStream();
                // base = "https://" + parts[1];
            }
            Request request = new Request();
            request.read(clientin);
        
            logger.info("Read request from browser : " + request.toString());
        
            if (_plugins != null) {
                for (int i=0; i<_plugins.length; i++) {
                    logger.info("Passing request to " + _plugins[i].getPluginName());
                    request = _plugins[i].interceptRequest(request);
                }
            }
                    
            // We've read the request, now send it to the server, and get the response
            logger.info("Sending request to server");
            Response response = new URLFetcher().fetchResponse(request);
            logger.info("Got " + response.getStatusLine());
            
            Response copyResponse = new Response(response);
            InputStream is = response.getContentStream();
            CopyInputStream responseContentStream = null;
            if (is != null) {
                responseContentStream = new CopyInputStream(is);
                copyResponse.setContentStream(responseContentStream);
                response.setContentStream(responseContentStream);
            }
                
            if (_plugins != null) {
                for (int i=0; i<_plugins.length; i++) {
                    response = _plugins[i].interceptResponse(request, response);
                }
            }
                    
            response.write(clientout);
            
            if (isSSL) {
                // close down the SSL stuff;
            }
            clientin.close();
            clientout.close();
            sock.close();
            logger.info("Finished writing response to the browser, now sending it to the model");
            
            // now call the model
            if (_webscarab != null) {
                if (responseContentStream != null) {
                    int available = responseContentStream.available();
                    if (available > 0) {
                        byte[] buf = new byte[available];
                        logger.info("Haven't completely written the content! Still " + available + " available");
                        while ((available = responseContentStream.read(buf))>0) {
                            logger.info("Read " + available + " bytes\n" + new String(buf));
                        }
                    }
                    copyResponse.setContent(responseContentStream.toByteArray());
                }
                logger.info("Creating conversation");
                Conversation c = new Conversation(request,copyResponse);
                logger.info("Created conversation OK");
                _webscarab.addConversation(c);
            }
        } catch (Exception e) {
            logger.warning("Got an error : " + e);
        } finally {
            try {
                logger.info("Closing client socket");
                sock.close();
            } catch (IOException ioe2) {
                logger.warning("Error closing client socket : " + ioe2);
            }
        }            
    }
    

    private SSLSocket connectLocal(Socket sock) throws IOException {
        OutputStream out = sock.getOutputStream();
        InputStream in = sock.getInputStream();
        
        
//        String proxyAuth = request.getHeader("Proxy-Authorization");
//        if (proxyAuth == null) {
//            proxyAuth = "";
//        }

        logger.info("Intercepting SSL connection!");
        try {
            out.write(("HTTP/1.0 200 Ok\r\n\r\n").getBytes());
            clientout.flush();
        } catch (IOException ioe) {
            logger.severe("IOException writing the CONNECT OK Response to the browser");
        }

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
                sock.close();
            } catch (IOException ioe) {}
            return null;
        }
        SSLSocketFactory factory = sslcontext.getSocketFactory();

        try {
            sslsock=(SSLSocket)factory.createSocket(sock,sock.getInetAddress().getHostName(),sock.getPort(),true);
            sslsock.setUseClientMode(false);
        } catch (IOException ioe) {
            logger.severe("Error layering SSL over the existing socket");
            try {
                sock.close();
            } catch (IOException ioe2) {}
            return null;
        }
        logger.info("Finished negotiating SSL - algorithm is " + sslsock.getSession().getCipherSuite());
        return sslsock;
//        logger.info("Read request from browser : " + request.getMethod() + " " + request.getURL());
//        if (!proxyAuth.equals("")) {
//            request.setHeader("Proxy-Authorization",proxyAuth);
//        }
//        return sslsock;
    }        
    
    
    private static synchronized String readLine(InputStream is) throws IOException {
        StringBuffer line = new StringBuffer();
        int i;
        byte[] b={(byte)0x00};
        i = is.read();
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a byte
            // we use an array because we can't concat a single byte :-(
            b[0] = (byte)(i & 0xFF);
            String input = new String(b,0,1);
            line = line.append(input);
            i = is.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = is.read();
        }
        return line.toString();
    }        
        
}
