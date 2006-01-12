/*
 * SSLContextManager.java
 *
 * Created on 12 January 2006, 09:06
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.httpclient;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 *
 * @author rdawes
 */
public class SSLContextManager {
    
    private Map _contextMaps = new HashMap();
    private SSLContext _noClientCertContext;
    private String _defaultKey = null;
    
    private static TrustManager[] _trustAllCerts = new TrustManager[] {
        new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }
    };
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of SSLContextManager */
    public SSLContextManager() {
        try {
            _noClientCertContext = SSLContext.getInstance("SSL");
            _noClientCertContext.init(null, _trustAllCerts, new SecureRandom());
        } catch (NoSuchAlgorithmException nsao) {
            _logger.severe("Could not get an instance of the SSL algorithm: " + nsao.getMessage());
        } catch (KeyManagementException kme) {
            _logger.severe("Error initialising the SSL Context: " + kme);
        }
    }
    
    public void setDefaultKey(String fingerprint) {
        _defaultKey = fingerprint;
    }
    
    public String getDefaultKey() {
        return _defaultKey;
    }
    
    public String loadPKCS12Certificate(String filename, String ksPassword, String keyPassword) throws IOException, KeyStoreException, CertificateException, KeyManagementException {
        // Open the file
        InputStream is = new FileInputStream(filename);
        if (is == null)
            throw new FileNotFoundException(filename + " could not be found");
        
        // create the keystore
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try {
            ks.load(is, ksPassword == null ? null : ksPassword.toCharArray());
        } catch (NoSuchAlgorithmException nsae) {
            _logger.severe("No such algorithm " + nsae.getMessage());
            return null;
        }
        String alias = (String) ks.aliases().nextElement();
        return createSSLContext(ks, alias, keyPassword);
    }
    
    public String createSSLContext(KeyStore ks, String alias, String keypassword) throws KeyManagementException {
        AliasKeyManager akm = new AliasKeyManager(ks, alias, keypassword);
        X509Certificate[] certs = akm.getCertificateChain(alias);
        
        String fingerprint = getKeyIdentifier(certs[0]);
        String dn = certs[0].getSubjectDN().getName();
        
        KeyManager[] managers = new KeyManager[] { akm };
        
        SSLContext sc;
        try {
            sc = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException nsao) {
            _logger.severe("Could not get an instance of the SSL algorithm: " + nsao.getMessage());
            return null;
        }
        sc.init(managers, _trustAllCerts, new SecureRandom());
        
        _contextMaps.put(fingerprint, sc);
        
        return fingerprint + " " + dn;
    }
    
    public void invalidateSessions() {
        invalidateSession(_noClientCertContext);
        Iterator it = _contextMaps.keySet().iterator();
        while (it.hasNext()) {
            invalidateSession((SSLContext)_contextMaps.get(it.next()));
        }
    }
    
    private void invalidateSession(SSLContext sc) {
        SSLSessionContext sslsc = sc.getClientSessionContext();
        if (sslsc != null) {
            int timeout = sslsc.getSessionTimeout();
            // force sessions to be timed out
            sslsc.setSessionTimeout(1);
            sslsc.setSessionTimeout(timeout);
        }
        sslsc = sc.getServerSessionContext();
        if (sslsc != null) {
            int timeout = sslsc.getSessionTimeout();
            // force sessions to be timed out
            sslsc.setSessionTimeout(1);
            sslsc.setSessionTimeout(timeout);
        }
    }
    
    public SSLContext getSSLContext(String fingerprint) {
        if (fingerprint == null || fingerprint.equals("none"))
            return _noClientCertContext;
        if (fingerprint.indexOf(" ")>0)
            fingerprint = fingerprint.substring(0, fingerprint.indexOf(" "));
        return (SSLContext) _contextMaps.get(fingerprint);
    }
    
    private String getKeyIdentifier(X509Certificate cert) {
        StringBuffer buff = new StringBuffer();
        byte[] fingerprint = cert.getExtensionValue("2.5.29.14");
        for (int i=4; i<Math.min(24,fingerprint.length); i++) {
            buff.append(Integer.toHexString((fingerprint[i] & 0xFF)|0x100).substring(1,3)).append(":");
        }
        return buff.toString().toUpperCase().substring(0, buff.length()-1);
    }
    
}
