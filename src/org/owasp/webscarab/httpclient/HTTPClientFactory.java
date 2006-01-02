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

/*
 * HttpClientFactory.java
 *
 * Created on August 19, 2004, 11:22 PM
 */

package org.owasp.webscarab.httpclient;

import java.io.FileInputStream;
import java.io.IOException;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLContext;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class HTTPClientFactory {
    
    private static HTTPClientFactory _instance = new HTTPClientFactory();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _httpProxy = "";
    private int _httpProxyPort = 80;
    private String _httpsProxy = "";
    private int _httpsProxyPort = 80;
    private String[] _noProxy = new String[0];
    
    private int _connectTimeout = 30000;
    private int _readTimeout = 0;
    
    private SSLContext _sslContext = null;
    
    private String _certFile = "";
    private String _keystorePassword = "";
    private String _keyPassword = "";
    
    private Authenticator _authenticator = null;
    
    // Create a trust manager that does not validate certificate chains
    private static TrustManager[] _trustAllCerts = new TrustManager[]{
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
    
    /** Creates a new instance of HttpClientFactory */
    protected HTTPClientFactory() {
        initSSLContext(null);
    }
    
    public static HTTPClientFactory getInstance() {
        return _instance;
    }
    
    public void setHttpProxy(String proxy, int port) {
        if (proxy == null) proxy = "";
        _httpProxy = proxy;
        if (port<1 || port > 65535) throw new IllegalArgumentException("Port is out of range: " + port);
        _httpProxyPort = port;
    }
    
    public String getHttpProxy() {
        return _httpProxy;
    }
    
    public int getHttpProxyPort() {
        return _httpProxyPort;
    }
    
    public void setHttpsProxy(String proxy, int port) {
        if (proxy == null) proxy = "";
        _httpsProxy = proxy;
        if (port<1 || port > 65535) throw new IllegalArgumentException("Port is out of range: " + port);
        _httpsProxyPort = port;
    }
    
    public String getHttpsProxy() {
        return _httpsProxy;
    }
    
    public int getHttpsProxyPort() {
        return _httpsProxyPort;
    }
    
    public void setNoProxy(String[] noProxy) {
        _noProxy = noProxy;
        if (_noProxy == null) _noProxy = new String[0];
    }
    
    public String[] getNoProxy() {
        return _noProxy;
    }
    
    public void setClientCertificateFile(String certFile, String keystorePassword, String keyPassword)
    throws IOException, KeyStoreException, CertificateException, UnrecoverableKeyException {
        _certFile = certFile;
        if (_certFile == null) _certFile = "";
        _keystorePassword = keystorePassword;
        if (_keystorePassword == null) _keystorePassword = "";
        _keyPassword = keyPassword;
        if (_keyPassword == null) _keyPassword = "";
        
        if (_certFile.equals("")) {
            initSSLContext(null);
        } else {
            try {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(_certFile), _keystorePassword.toCharArray());
                kmf.init(ks, _keyPassword.toCharArray());
                initSSLContext(kmf.getKeyManagers());
            } catch (NoSuchAlgorithmException nsae) {
                _logger.severe("No SunX509 suport: " + nsae);
                initSSLContext(null);
            }
        }
    }
    
    public String getClientCertificateFile() {
        return _certFile;
    }
    
    public String getClientKeystorePassword() {
        return _keystorePassword;
    }
    
    public String getClientKeyPassword() {
        return _keyPassword;
    }
    
    private void initSSLContext(KeyManager[] managers) {
        try {
            _sslContext = SSLContext.getInstance("SSL");
            _sslContext.init(managers, _trustAllCerts, new SecureRandom());
        } catch (NoSuchAlgorithmException nsae) {
            _sslContext = null;
        } catch (KeyManagementException kme) {
            _sslContext = null;
        }
    }
    
    public void setTimeouts(int connectTimeout, int readTimeout) {
        _connectTimeout = connectTimeout;
        _readTimeout = readTimeout;
    }
    
    public void setAuthenticator(Authenticator authenticator) {
        _authenticator = authenticator;
    }
    
    public Authenticator getAuthenticator() {
        return _authenticator;
    }
    
    public HTTPClient getHTTPClient() {
        URLFetcher uf = new URLFetcher();
        uf.setHttpProxy(_httpProxy, _httpProxyPort);
        uf.setHttpsProxy(_httpsProxy, _httpsProxyPort);
        uf.setNoProxy(_noProxy);
        uf.setSSLContext(_sslContext);
        uf.setTimeouts(_connectTimeout, _readTimeout);
        uf.setAuthenticator(_authenticator);
        return uf;
    }
    
}
