/*
 * SSLKeyManager.java
 *
 * Created on 20 July 2005, 10:05
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import java.net.Socket;

import java.util.Map;
import java.util.TreeMap;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.Enumeration;

import java.util.logging.Logger;
import java.util.logging.Level;

import java.io.IOException;
import java.io.FileInputStream;

import java.beans.PropertyChangeSupport;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

import org.owasp.webscarab.model.Preferences;

/**
 *
 * @author rdawes
 */
public class SSLKeyManager implements X509KeyManager {
    
    public final static String KEY_PROPERTY = "KEYS";
    public final static String SELECTED_KEY = "SELECTED KEY";
    
    private static final String SEP = " -:- ";
    
    private String _preferredStore = null;
    private String _preferredAlias = null;
    private X509KeyManager _preferredKeyManager = null;
    
    private Map _stores = new TreeMap();
    private Map _managers = new TreeMap();
    
    private PropertyChangeSupport _changeSupport = new PropertyChangeSupport(this);
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /**
     * Creates a new instance of SSLKeyManager
     */
    public SSLKeyManager() {
        _logger.setLevel(Level.FINEST);
        if (System.getProperty("os.name", "").toLowerCase().indexOf("windows")>-1) {
            Provider provider;
            try {
                provider = (Provider) Class.forName("se.assembla.jce.provider.ms.MSProvider").newInstance();
            } catch (Throwable t) {
                return;
            }
            try {
                Security.insertProviderAt(provider, 2);
                KeyStore ks = KeyStore.getInstance("msks", "assembla");
                ks.load(null, null);
                addKeyStore("Microsoft CAPI store", ks, null);
            } catch (Exception e) {
                _logger.info("Microsoft CAPI interface not available: " + e);
            }
        }
    }
    
    public synchronized String addPKCS12KeyStore(String filename, String keyStorePassword, String keyPassword) throws KeyStoreException, UnrecoverableKeyException, IOException, CertificateException {
        if (keyStorePassword == null) keyStorePassword = "";
        if (keyPassword == null) keyPassword = keyStorePassword;
        
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(filename), keyStorePassword.toCharArray());
            String description = "PKCS#12: " + filename;
            addKeyStore(description, ks, keyPassword.toCharArray());
            
            return description;
        } catch (NoSuchAlgorithmException nsae) {
            _logger.severe("No SunX509 suport: " + nsae);
            return null;
        }
    }
    
    public synchronized void addKeyStore(String description, KeyStore ks, char[] password) throws KeyStoreException, UnrecoverableKeyException {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, password);
            KeyManager km = kmf.getKeyManagers()[0];
            if (!(km instanceof X509KeyManager))
                throw new KeyStoreException("KeyManager for " + description + "is not X509!");
            _stores.put(description, ks);
            _managers.put(description, km);
        } catch (NoSuchAlgorithmException nsae) {
            _logger.severe("This should never happen! SunX509 algorithm not found: " + nsae.getMessage());
        }
        _changeSupport.firePropertyChange(KEY_PROPERTY, null, null);
    }
    
    public String[] getKeyStoreDescriptions() {
        return (String[]) _stores.keySet().toArray(new String[0]);
    }
    
    public synchronized void removeKeyStore(String description) {
        _stores.remove(description);
        _changeSupport.firePropertyChange(KEY_PROPERTY, null, null);
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.addPropertyChangeListener(listener);
    }
    
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.removePropertyChangeListener(listener);
    }
    
    public synchronized String[] getAliases(String description) {
        KeyStore ks = (KeyStore) _stores.get(description);
        if (ks == null) {
            return null;
        }
        List aliases = new ArrayList();
        try {
            Enumeration e = ks.aliases();
            while (e.hasMoreElements()) {
                aliases.add(e.nextElement());
            }
        } catch (KeyStoreException kse) {
            _logger.severe("Error enumerating aliases: " + kse.getMessage());
        }
        return (String[]) aliases.toArray(new String[0]);
    }
    
    public synchronized boolean setPreferredAlias(String description, String alias) {
        String old = String.valueOf(_preferredStore) + SEP + String.valueOf(_preferredAlias);
        if (description != null && alias != null) {
            KeyStore ks = (KeyStore) _stores.get(description);
            try {
                if (ks.isKeyEntry(alias)) {
                    _preferredKeyManager = (X509KeyManager) _managers.get(description);
                    _preferredStore = description;
                    _preferredAlias = alias;
                    String now = String.valueOf(_preferredStore) + SEP + String.valueOf(_preferredAlias);
                    if (!now.equals(old)) 
                        _changeSupport.firePropertyChange(SELECTED_KEY, null, null);
                    return true;
                }
            } catch (KeyStoreException kse) {
                _logger.severe("Unexpected KeyStore exception: " + kse.getMessage());
            }
        }
        _preferredKeyManager = null;
        _preferredStore = null;
        _preferredAlias = null;
        String now = String.valueOf(_preferredStore) + SEP + String.valueOf(_preferredAlias);
        if (!now.equals(old)) 
            _changeSupport.firePropertyChange(SELECTED_KEY, null, null);
        return false;
    }
    
    public String getPreferredStore() {
        return _preferredStore;
    }
    
    public String getPreferredAlias() {
        return _preferredAlias;
    }
    
    public synchronized String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        _logger.entering(getClass().getName(), "chooseClientAlias");
        if (_preferredStore != null && _preferredAlias != null)
            return _preferredStore + SEP + _preferredAlias;
        return null;
    }
    
    public synchronized String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        if (_preferredKeyManager != null)
            return _preferredKeyManager.chooseServerAlias(keyType, issuers, socket);
        
        Iterator it = _managers.keySet().iterator();
        while (it.hasNext()) {
            String source = (String) it.next();
            X509KeyManager km = (X509KeyManager) _managers.get(source);
            String alias = km.chooseServerAlias(keyType, issuers, socket);
            if (alias != null) return source + SEP + alias;
        }
        return null;
    }
    
    public synchronized X509Certificate[] getCertificateChain(String alias) {
        String[] parts = alias.split(SEP, 2);
        String description = parts[0];
        alias = parts[1];
        X509KeyManager km = (X509KeyManager) _managers.get(description);
        return km.getCertificateChain(alias);
    }
    
    public synchronized String[] getClientAliases(String keyType, Principal[] issuers) {
        if (_preferredKeyManager != null)
            return _preferredKeyManager.getClientAliases(keyType, issuers);
        
        List allAliases = new ArrayList();
        Iterator it = _managers.keySet().iterator();
        while (it.hasNext()) {
            String source = (String) it.next();
            X509KeyManager km = (X509KeyManager) _managers.get(source);
            String[] aliases = km.getClientAliases(keyType, issuers);
            if (aliases != null) {
                for (int i=0; i<aliases.length; i++) {
                    allAliases.add(source + SEP + aliases[i]);
                }
            }
        }
        return (String[]) allAliases.toArray(new String[0]);
    }
    
    public synchronized PrivateKey getPrivateKey(String alias) {
        String[] parts = alias.split(SEP, 2);
        String description = parts[0];
        alias = parts[1];
        X509KeyManager km = (X509KeyManager) _managers.get(description);
        return km.getPrivateKey(alias);
    }
    
    public synchronized String[] getServerAliases(String keyType, Principal[] issuers) {
        if (_preferredKeyManager != null)
            return _preferredKeyManager.getServerAliases(keyType, issuers);
        
        List allAliases = new ArrayList();
        Iterator it = _managers.keySet().iterator();
        while (it.hasNext()) {
            String source = (String) it.next();
            X509KeyManager km = (X509KeyManager) _managers.get(source);
            String[] aliases = km.getServerAliases(keyType, issuers);
            if (aliases != null) {
                for (int i=0; i<aliases.length; i++) {
                    allAliases.add(source + SEP + aliases[i]);
                }
            }
        }
        return (String[]) allAliases.toArray(new String[0]);
    }
    
}
