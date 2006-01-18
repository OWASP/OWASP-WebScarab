/*
 * AliasKeyManager.java
 *
 * Created on 10 January 2006, 10:59
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.httpclient;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.X509KeyManager;

/**
 * A KeyManager implementation that only ever selects a single alias,
 * rather than considering the "best" alias for the circumstances
 * @author rdawes
 */
public class AliasKeyManager implements X509KeyManager {
    
    private KeyStore _ks;
    private String _alias;
    private String _keyPassword;
    
    /**
     * Creates a new instance of AliasKeyManager
     * @param ks The KeyStore that contains the keypair to use
     * @param password the password for the key (not the keystore)
     * @param alias the alias of the certificate to use
     */
    public AliasKeyManager(KeyStore ks, String alias, String keyPassword) {
        _ks = ks;
        _alias = alias;
        _keyPassword = keyPassword;
    }
    
    public String chooseClientAlias(String[] str, Principal[] principal, Socket socket) {
        return _alias;
    }

    public String chooseServerAlias(String str, Principal[] principal, Socket socket) {
        return _alias;
    }

    public X509Certificate[] getCertificateChain(String alias) {
        try {
            Certificate[] certs = _ks.getCertificateChain(alias);
            if (certs == null) return null;
            X509Certificate[] x509certs = new X509Certificate[certs.length];
            for (int i=0; i<certs.length; i++) {
                x509certs[i]=(X509Certificate) certs[i];
            }
            return x509certs;
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
            return null;
        }
    }

    public String[] getClientAliases(String str, Principal[] principal) {
        return new String[] { _alias };
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) _ks.getKey(alias, _keyPassword.toCharArray());
        } catch (KeyStoreException kse) {
            kse.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException nsao) {
            nsao.printStackTrace();
            return null;
        } catch (UnrecoverableKeyException uke) {
            uke.printStackTrace();
            return null;
        }
    }

    public String[] getServerAliases(String str, Principal[] principal) {
        return new String[] { _alias };
    }
    
}
