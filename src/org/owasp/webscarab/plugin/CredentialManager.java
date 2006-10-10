/*
 * CredentialManager.java
 *
 * Created on 04 January 2006, 08:25
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.owasp.webscarab.httpclient.Authenticator;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author rdawes
 */
public class CredentialManager implements Authenticator {
    
    // contains Maps per host, indexed by Realm
    private Map _basicCredentials = new TreeMap();
    private Map _domainCredentials = new TreeMap();
    
    private CredentialManagerUI _ui = null;
    
    /** Creates a new instance of CredentialManager */
    public CredentialManager() {
    }
    
    public void setUI(CredentialManagerUI ui) {
        _ui = ui;
    }
    
    public synchronized String getCredentials(HttpUrl url, String[] challenges) {
        String creds = getPreferredCredentials(url.getHost(), challenges);
        if (creds != null) return creds;
        boolean prompt = Boolean.valueOf(Preferences.getPreference("WebScarab.promptForCredentials", "false")).booleanValue();
        if (prompt && _ui != null && challenges != null && challenges.length > 0) {
            boolean ask = false;
            for (int i=0; i<challenges.length; i++)
                if (challenges[i].startsWith("Basic") || challenges[i].startsWith("NTLM") || challenges[i].startsWith("Negotiate"))
                    ask = true;
            if (ask)
                _ui.requestCredentials(url.getHost(), challenges);
        }
        return getPreferredCredentials(url.getHost(), challenges);
    }
    
    public synchronized String getProxyCredentials(String hostname, String[] challenges) {
        String creds = getPreferredCredentials(hostname, challenges);
        if (creds != null) return creds;
        boolean prompt = Boolean.valueOf(Preferences.getPreference("WebScarab.promptForCredentials", "false")).booleanValue();
        if (prompt && _ui != null && challenges != null && challenges.length > 0) {
            boolean ask = false;
            for (int i=0; i<challenges.length; i++)
                if (challenges[i].startsWith("Basic") || challenges[i].startsWith("NTLM") || challenges[i].startsWith("Negotiate"))
                    ask = true;
            if (ask)
                _ui.requestCredentials(hostname, challenges);
        }
        return getPreferredCredentials(hostname, challenges);
    }
    
    public void addBasicCredentials(BasicCredential cred) {
        if ((cred.getUsername() == null || cred.getUsername().equals("")) && (cred.getPassword() == null || cred.getPassword().equals(""))) return;
        Map realms = (Map) _basicCredentials.get(cred.getHost());
        if (realms == null) {
            realms = new TreeMap();
            _basicCredentials.put(cred.getHost(), realms);
        }
        realms.put(cred.getRealm(), cred);
    }
    
    public void addDomainCredentials(DomainCredential cred) {
        if ((cred.getUsername() == null || cred.getUsername().equals("")) && (cred.getPassword() == null || cred.getPassword().equals(""))) return;
        _domainCredentials.put(cred.getHost(), cred);
    }
    
    public int getBasicCredentialCount() {
        return getAllBasicCredentials().length;
    }
    
    public BasicCredential getBasicCredentialAt(int index) {
        return getAllBasicCredentials()[index];
    }
    
    public void deleteBasicCredentialAt(int index) {
        int i = -1;
        Iterator hosts = _basicCredentials.keySet().iterator();
        while (hosts.hasNext()) {
            Map realms = (Map) _basicCredentials.get(hosts.next());
            Iterator realm = realms.keySet().iterator();
            while (realm.hasNext()) {
                Object key = realm.next();
                i++;
                if (i == index)
                    realms.remove(key);
            }
        }
    }
    
    public int getDomainCredentialCount() {
        return _domainCredentials.entrySet().size();
    }
    
    public DomainCredential getDomainCredentialAt(int index) {
        List all = new ArrayList();
        Iterator hosts = _domainCredentials.keySet().iterator();
        while (hosts.hasNext())
            all.add(_domainCredentials.get(hosts.next()));
        return (DomainCredential) all.toArray(new DomainCredential[0])[index];
    }
    
    public void deleteDomainCredentialAt(int index) {
        int i = -1;
        Iterator hosts = _domainCredentials.keySet().iterator();
        while (hosts.hasNext()) {
            Object key = hosts.next();
            i++;
            if (i == index)
                _domainCredentials.remove(key);
        }
    }
    
    private BasicCredential[] getAllBasicCredentials() {
        List all = new ArrayList();
        Iterator hosts = _basicCredentials.keySet().iterator();
        while (hosts.hasNext()) {
            Map realms = (Map) _basicCredentials.get(hosts.next());
            Iterator realm = realms.keySet().iterator();
            while (realm.hasNext())
                all.add(realms.get(realm.next()));
        }
        return (BasicCredential[]) all.toArray(new BasicCredential[0]);
    }
    
    private String getPreferredCredentials(String host, String[] challenges) {
        // we don't do pre-emptive auth at all
        if (challenges == null || challenges.length == 0)
            return null;
        for (int i=0; i<challenges.length; i++) {
            if (challenges[i].startsWith("Basic")) {
                String creds = getBasicCredentials(host, challenges[i]);
                if (creds != null) return "Basic " + creds;
            }
        }
        for (int i=0; i<challenges.length; i++) {
            if (challenges[i].startsWith("NTLM")) {
                String creds = getDomainCredentials(host);
                if (creds != null) return "NTLM " + creds;
            }
        }
        for (int i=0; i<challenges.length; i++) {
            if (challenges[i].startsWith("Negotiate")) {
                String creds = getDomainCredentials(host);
                if (creds != null) return "Negotiate " + creds;
            }
        }
        return null;
    }
    
    private String getBasicCredentials(String host, String challenge) {
        String realm = challenge.substring("Basic Realm=\"".length(), challenge.length()-1);
        Map realms = (Map) _basicCredentials.get(host);
        if (realms == null) return null;
        BasicCredential cred = (BasicCredential) realms.get(realm);
        if (cred == null) return null;
        String encoded = cred.getUsername() + ":" + cred.getPassword();
        return Encoding.base64encode(encoded.getBytes());
    }
    
    private String getDomainCredentials(String host) {
        DomainCredential cred = (DomainCredential) _domainCredentials.get(host);
        if (cred == null) return null;
        String encoded = cred.getDomain() + "\\" + cred.getUsername() + ":" + cred.getPassword();
        return Encoding.base64encode(encoded.getBytes());
    }
    
}
