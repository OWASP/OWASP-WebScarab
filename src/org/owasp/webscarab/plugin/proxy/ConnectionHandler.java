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
import org.owasp.webscarab.util.HtmlEncoder;

public class ConnectionHandler implements Runnable {

    private static SSLSocketFactory _factory = null;

    private static String _keystore = "server.p12";
    private static char[] _keystorepass = "password".toCharArray();
    private static char[] _keypassword = "password".toCharArray();

    private ProxyPlugin[] _plugins = null;
    private Proxy _proxy;
    private Socket _sock = null;
    private HttpUrl _base;
    private NetworkSimulator _simulator;

    private HTTPClient _httpClient = null;

    private Logger _logger = Logger.getLogger(getClass().getName());

    private InputStream _clientIn = null;
    private OutputStream _clientOut = null;
    private InputStream _serverIn = null;
    private OutputStream _serverOut = null;

    public ConnectionHandler(Proxy proxy, Socket sock, HttpUrl base, NetworkSimulator simulator) {
        _proxy = proxy;
        _sock = sock;
        _base = base;
        _simulator = simulator;
        _plugins = _proxy.getPlugins();
        try {
            _sock.setTcpNoDelay(true);
            _sock.setSoTimeout(30 * 1000);
        } catch (SocketException se) {
            _logger.warning("Error setting socket parameters");
        }
    }

    public void run() {
        ScriptableConnection connection = new ScriptableConnection(_sock);
        _proxy.allowClientConnection(connection);
        if (_sock.isClosed()) return;

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
        ConversationID id = null;
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
                if (_base.getScheme().equals("https")) {
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
            String keepAlive = null;
            String version = null;

            do {
                id = null;
                // if we are reading the first from a reverse proxy, or the
                // continuation of a CONNECT from a normal proxy
                // read the request, otherwise we already have it.
                if (request == null) {
                    request = new Request();
                    _logger.fine("Reading request from the browser");
                    request.read(_clientIn, _base);
                    if (request.getMethod() == null || request.getURL() == null) {
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

                // report the request to the listener, and get the allocated ID
                id = _proxy.gotRequest(request);

                // pass the request for possible modification or analysis
                connection.setRequest(request);
                connection.setResponse(null);
                _proxy.interceptRequest(connection);
                request = connection.getRequest();
                Response response = connection.getResponse();

                if (request == null) throw new IOException("Request was cancelled");
                if (response != null) {
                    _proxy.failedResponse(id, "Response provided by script");
                    _proxy = null;
                } else {

                    // pass the request through the plugins, and return the response
                    try {
                        response = hc.fetchResponse(request);
                        if (response.getRequest() != null) request = response.getRequest();
                    } catch (IOException ioe) {
                        _logger.severe("IOException retrieving the response for " + request.getURL() + " : " + ioe);
                        ioe.printStackTrace();
                        response = errorResponse(request, ioe);
                        // prevent the conversation from being submitted/recorded
                        _proxy.failedResponse(id, ioe.toString());
                        _proxy = null;
                    }
                    if (response == null) {
                        _logger.severe("Got a null response from the fetcher");
                        _proxy.failedResponse(id, "Null response");
                        return;
                    }
                }

                if (_proxy != null) {
                    // pass the response for analysis or modification by the scripts
                    connection.setResponse(response);
                    _proxy.interceptResponse(connection);
                    response = connection.getResponse();
                }

                if (response == null) throw new IOException("Response was cancelled");

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
                // this should not happen, but might if a proxy plugin is careless
                if (response.getRequest() == null) {
                    _logger.warning("Response had no associated request!");
                    response.setRequest(request);
                }
                if (_proxy != null && !request.getMethod().equals("CONNECT")) {
                    _proxy.gotResponse(id, response);
                }

                keepAlive = response.getHeader("Connection");
                version = response.getVersion();

                request = null;

                _logger.fine("Version: " + version + " Connection: " + connection);
            } while ((version.equals("HTTP/1.0") && "keep-alive".equalsIgnoreCase(keepAlive)) ||
            (version.equals("HTTP/1.1") && !"close".equalsIgnoreCase(keepAlive)));
            _logger.fine("Finished handling connection");
        } catch (Exception e) {
            if (id != null) _proxy.failedResponse(id, e.getMessage());
            _logger.severe("ConnectionHandler got an error : " + e);
            e.printStackTrace();
        } finally {
            try {
                if (_clientIn != null) _clientIn.close();
                if (_clientOut != null) _clientOut.close();
                if (_sock != null && !_sock.isClosed()) {
                    _sock.close();
                }
            } catch (IOException ioe) {
                _logger.warning("Error closing client socket : " + ioe);
            }
        }
    }

    private void initSSL() {
        KeyStore ks = null;
        KeyManagerFactory kmf = null;
        SSLContext sslcontext = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            InputStream is = getClass().getClassLoader().getResourceAsStream(_keystore);
            if (is == null) throw new NullPointerException("No keystore found!!");
            ks.load(is, _keystorepass);
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, _keypassword);
            sslcontext = SSLContext.getInstance("SSLv3");
            sslcontext.init(kmf.getKeyManagers(), null, null);
            _factory = sslcontext.getSocketFactory();
            _logger.info("Initialised SSL handler OK");
        } catch (Exception e) {
            _logger.severe("Exception accessing keystore: " + e);
            _factory = null;
        }
    }

    private Socket negotiateSSL(Socket sock) throws Exception {
        if (_factory == null) initSSL();
        SSLSocket sslsock;
        try {
            sslsock=(SSLSocket)_factory.createSocket(sock,sock.getInetAddress().getHostName(),sock.getPort(),true);
            sslsock.setUseClientMode(false);
            _logger.fine("Finished negotiating SSL - algorithm is " + sslsock.getSession().getCipherSuite());
            return sslsock;
        } catch (Exception e) {
            _logger.severe("Error layering SSL over the socket: " + e);
            throw e;
        }
    }

    private Response errorResponse(Request request, Exception e) {
        Response response = new Response();
        response.setRequest(request);
        response.setVersion("HTTP/1.0");
        response.setStatus("500");
        response.setMessage("WebScarab error");
        response.setHeader("Content-Type","text/html");
        response.setHeader("Connection","Close");
        String template = "<HTML><HEAD><TITLE>WebScarab Error</TITLE></HEAD>";
        template = template + "<BODY>WebScarab encountered an error trying to retrieve <P><pre>" + HtmlEncoder.encode(request.toString()) + "</pre><P>";
        template = template + "The error was : <P><pre>" + HtmlEncoder.encode(e.getLocalizedMessage()) + "\n";
        StackTraceElement[] trace = e.getStackTrace();
        if (trace != null) {
            for (int i=0; i<trace.length; i++) {
                template = template + "\tat " + trace[i].getClassName() + "." + trace[i].getMethodName() + "(";
                if (trace[i].getLineNumber() == -2) {
                    template = template + "Native Method";
                } else if (trace[i].getLineNumber() == -1) {
                    template = template + "Unknown Source";
                } else {
                    template = template + trace[i].getFileName() + ":" + trace[i].getLineNumber();
                }
                template = template + ")\n";
            }
        }
        template = template + "</pre><P></HTML>";
        response.setContent(template.getBytes());
        return response;
    }

}
