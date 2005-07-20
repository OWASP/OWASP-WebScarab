/*
 * AggregateKeyManager.java
 *
 * Created on 20 July 2005, 10:05
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.httpclient;

import javax.net.ssl.X509KeyManager;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.net.Socket;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author rdawes
 */
public class AggregateKeyManager implements X509KeyManager {
    
    private static final String SEP = " -:- ";
    
    private Map _managers = new HashMap();
    
    /** Creates a new instance of AggregateKeyManager */
    public AggregateKeyManager() {
    }
    
    public synchronized void addKeyManager(String source, X509KeyManager km) {
        _managers.put(source, km);
    }
    
    public synchronized void removeKeyManager(String source) {
        _managers.remove(source);
    }
    
    public synchronized String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        Iterator it = _managers.keySet().iterator();
        while (it.hasNext()) {
            String source = (String) it.next();
            X509KeyManager km = (X509KeyManager) _managers.get(source);
            String alias = km.chooseClientAlias(keyType, issuers, socket);
            if (alias != null) return source + SEP + alias;
        }
        return null;
    }

    public synchronized String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
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
        String source = parts[0];
        alias = parts[1];
        X509KeyManager km = (X509KeyManager) _managers.get(source);
        return km.getCertificateChain(alias);
    }

    public synchronized String[] getClientAliases(String keyType, Principal[] issuers) {
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
        String source = parts[0];
        alias = parts[1];
        X509KeyManager km = (X509KeyManager) _managers.get(source);
        return km.getPrivateKey(alias);
    }

    public synchronized String[] getServerAliases(String keyType, Principal[] issuers) {
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
