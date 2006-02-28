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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.owasp.webscarab.util.Encoding;
import org.owasp.webscarab.util.NullComparator;

/**
 *
 * @author rdawes
 */
public class SSLContextManager {
    
    private Map _contextMaps = new TreeMap(new NullComparator());
    private SSLContext _noClientCertContext;
    private String _defaultKey = null;
    private Map _aliasPasswords = new HashMap();
    private List _keyStores = new ArrayList();
    private Map _keyStoreDescriptions = new HashMap();
    
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
        try {
            initMSCAPI();
        } catch (Exception e) {}
    }
    
    public boolean isProviderAvailable(String type) {
        try {
            if (type.equals("PKCS11")) {
                Class.forName("sun.security.pkcs11.SunPKCS11");
            } else if (type.equals("msks")) {
                Class.forName("se.assembla.jce.provider.ms.MSProvider");
            }
        } catch (Throwable t) {
            return false;
        }
        return true;
    }
    
    private boolean isProviderLoaded(String keyStoreType) {
        return Security.getProvider(keyStoreType) != null ? true : false;
    }
    
    private int addKeyStore(KeyStore ks, String description) {
        int index = _keyStores.indexOf(ks);
        if (index == -1) {
            _keyStores.add(ks);
            index = _keyStores.size() - 1;
        }
        _keyStoreDescriptions.put(ks, description);
        return index;
    }
    
    public int getKeyStoreCount() {
        return _keyStores.size();
    }
    
    public String getKeyStoreDescription(int keystoreIndex) {
        return (String) _keyStoreDescriptions.get(_keyStores.get(keystoreIndex));
    }
    
    public int getAliasCount(int keystoreIndex) {
        return getAliases((KeyStore) _keyStores.get(keystoreIndex)).length;
    }
    
    public String getAliasAt(int keystoreIndex, int aliasIndex) {
        return getAliases((KeyStore) _keyStores.get(keystoreIndex))[aliasIndex];
    }
    
    private String[] getAliases(KeyStore ks) {
        List aliases = new ArrayList();
        try {
            Enumeration en = ks.aliases();
            while (en.hasMoreElements()) {
                String alias = (String) en.nextElement();
                if (ks.isKeyEntry(alias))
                    aliases.add(alias);
            }
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
        }
        return (String[]) aliases.toArray(new String[0]);
    }
    
    public Certificate getCertificate(int keystoreIndex, int aliasIndex) {
        try {
            KeyStore ks = (KeyStore) _keyStores.get(keystoreIndex);
            String alias = getAliasAt(keystoreIndex, aliasIndex);
            return ks.getCertificate(alias);
        } catch (Exception e) {
            return null;
        }
    }
    
    public String getFingerPrint(Certificate cert) throws KeyStoreException {
        if (!(cert instanceof X509Certificate)) return null;
        StringBuffer buff = new StringBuffer();
        X509Certificate x509 = (X509Certificate) cert;
        try {
            String fingerprint = Encoding.hashMD5(cert.getEncoded());
            for (int i=0; i<fingerprint.length(); i+=2) {
                buff.append(fingerprint.substring(i, i+1)).append(":");
            }
            buff.deleteCharAt(buff.length()-1);
        } catch (CertificateEncodingException e) {
            throw new KeyStoreException(e.getMessage());
        }
        String dn = x509.getSubjectDN().getName();
        _logger.info("Fingerprint is " + buff.toString().toUpperCase());
        return buff.toString().toUpperCase() + " " + dn;
    }
    
    public boolean isKeyUnlocked(int keystoreIndex, int aliasIndex) {
        KeyStore ks = (KeyStore) _keyStores.get(keystoreIndex);
        String alias = getAliasAt(keystoreIndex, aliasIndex);
        
        Map pwmap = (Map) _aliasPasswords.get(ks);
        if (pwmap == null) return false;
        return pwmap.containsKey(alias);
    }
    
    public void setDefaultKey(String fingerprint) {
        _defaultKey = fingerprint;
    }
    
    public String getDefaultKey() {
        return _defaultKey;
    }
    
    private void initMSCAPI()
    throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        try {
            if (!isProviderAvailable("msks")) return;
            
            Provider mscapi = (Provider) Class.forName("se.assembla.jce.provider.ms.MSProvider").newInstance();
            Security.addProvider(mscapi);
            
            // init the key store
            KeyStore ks = KeyStore.getInstance("msks", "assembla");
            ks.load(null, null);
            addKeyStore(ks, "Microsoft CAPI Store");
        } catch (Exception e) {
            System.err.println("Error instantiating the MSCAPI provider");
            e.printStackTrace();
        }
    }
    
    public int initPKCS11(String name, String library, String kspassword)
    throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        try {
            if (!isProviderAvailable("PKCS11")) return -1;
            
            // Set up a virtual config file
            StringBuffer cardConfig = new StringBuffer();
            cardConfig.append("name = ").append(name).append("\n");
            cardConfig.append("library = ").append(library).append("\n");
            InputStream is = new ByteArrayInputStream(cardConfig.toString().getBytes());
            
            // create the provider
            Class pkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
            Constructor c = pkcs11Class.getConstructor(new Class[] { InputStream.class });
            Provider pkcs11 = (Provider) c.newInstance(new Object[] { is });
            Security.addProvider(pkcs11);
            
            // init the key store
            KeyStore ks = KeyStore.getInstance("PKCS11");
            ks.load(null, kspassword == null ? null : kspassword.toCharArray());
            return addKeyStore(ks, "PKCS#11");
        } catch (Exception e) {
            System.err.println("Error instantiating the PKCS11 provider");
            e.printStackTrace();
            return -1;
        }
    }
    
    public int loadPKCS12Certificate(String filename, String ksPassword)
    throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        // Open the file
        InputStream is = new FileInputStream(filename);
        if (is == null)
            throw new FileNotFoundException(filename + " could not be found");
        
        // create the keystore
        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(is, ksPassword == null ? null : ksPassword.toCharArray());
        return addKeyStore(ks, "PKCS#12 - " + filename);
    }
    
    private void saveKey(KeyStore ks, String alias, String keypassword) {
        Map pwmap = (Map) _aliasPasswords.get(ks);
        if (pwmap == null) {
            pwmap = new TreeMap(new NullComparator());
            _aliasPasswords.put(ks, pwmap);
        }
        pwmap.put(alias, keypassword);
    }
    
    
    public void unlockKey(int keystoreIndex, int aliasIndex, String keyPassword) throws KeyStoreException, KeyManagementException {
        KeyStore ks = (KeyStore) _keyStores.get(keystoreIndex);
        String alias = getAliasAt(keystoreIndex, aliasIndex);
        
        AliasKeyManager akm = new AliasKeyManager(ks, alias, keyPassword);
        
        String fingerprint = getFingerPrint(getCertificate(keystoreIndex, aliasIndex));
        
        if (fingerprint == null) {
            _logger.severe("No fingerprint found");
            return;
        }
        
        SSLContext sc;
        try {
            sc = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException nsao) {
            _logger.severe("Could not get an instance of the SSL algorithm: " + nsao.getMessage());
            return;
        }
        
        sc.init(new KeyManager[] { akm }, _trustAllCerts, new SecureRandom());
        
        String key = fingerprint;
        if (key.indexOf(" ")>0)
            key = key.substring(0, key.indexOf(" "));
        _contextMaps.put(key, sc);
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
        _logger.info("Requested SSLContext for " + fingerprint);
        
        if (fingerprint == null || fingerprint.equals("none"))
            return _noClientCertContext;
        if (fingerprint.indexOf(" ")>0)
            fingerprint = fingerprint.substring(0, fingerprint.indexOf(" "));
        return (SSLContext) _contextMaps.get(fingerprint);
    }
    
}
