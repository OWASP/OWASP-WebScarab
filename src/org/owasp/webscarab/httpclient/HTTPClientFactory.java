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
    
    private int _timeout = 30000;
    
    private SSLContext _sslContext = null;
    
    private String _certFile = "";
    private String _keystorePassword = "";
    private String _keyPassword = "";
    
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
    
    public HTTPClient getHTTPClient() {
        URLFetcher uf = new URLFetcher();
        uf.setHttpProxy(_httpProxy, _httpProxyPort);
        uf.setHttpsProxy(_httpsProxy, _httpsProxyPort);
        uf.setNoProxy(_noProxy);
        uf.setSSLContext(_sslContext);
        uf.setTimeout(_timeout);
        return uf;
    }
    
}
