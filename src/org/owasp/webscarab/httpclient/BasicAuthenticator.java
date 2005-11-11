/*
 * BasicAuthenticator.java
 *
 * Created on 21 June 2005, 09:29
 */

package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.util.Encoding;

import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

import java.beans.PropertyChangeSupport;
import java.beans.PropertyChangeListener;

/**
 *
 * @author  rogan
 */
public class BasicAuthenticator implements Authenticator {
    
    private Map _credentials = new TreeMap();
    private PropertyChangeSupport _changeSupport = new PropertyChangeSupport(this);
    
    /** Creates a new instance of BasicAuthenticator */
    public BasicAuthenticator() {
    }
    
    public synchronized String getChallengeResponse(HttpUrl url, String challenge, boolean first) {
        // check if this is a non-preemptive auth attempt?
        if (challenge != null && !challenge.startsWith("Basic")) return null;
        // challenge is null indicates preemptive
        // otherwise, it is definitely a Basic challenge
        String host = url.getHost();
        String path = url.getPath();
        Iterator it = _credentials.keySet().iterator();
        String response = null;
        // find the best match in the credentials we have collected
        while (it.hasNext()) {
            HttpUrl curl = (HttpUrl) it.next();
            String chost = curl.getHost();
            if (!host.equals(chost)) continue;
            String cpath = curl.getPath();
            if (!path.startsWith(cpath)) continue;
            response = (String) _credentials.get(curl);
        }
        return response;
    }
    
    public synchronized void addCredential(HttpUrl url, String username, String password) {
        String credential = username+":"+password;
        credential = Encoding.base64encode(credential.getBytes());
        if (url.getParameters() != null) url = url.getParentUrl();
        if (!url.toString().endsWith("/")) url = url.getParentUrl();
        _credentials.put(url, credential);
    }
    
    public synchronized HttpUrl[] getAuthenticatedUrls() {
        return (HttpUrl[]) _credentials.keySet().toArray(new HttpUrl[0]);
    }
    
    public synchronized String getUserName(HttpUrl url) {
        String credential = (String) _credentials.get(url);
        if (credential == null) return null;
        credential = new String(Encoding.base64decode(credential));
        int colon = credential.indexOf(":");
        return credential.substring(0,colon);
    }
    
    public synchronized String getPassword(HttpUrl url) {
        String credential = (String) _credentials.get(url);
        if (credential == null) return null;
        credential = new String(Encoding.base64decode(credential));
        int colon = credential.indexOf(":");
        return credential.substring(colon+1);
    }
    
    public synchronized void removeCredential(HttpUrl url) {
        _credentials.remove(url);
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.addPropertyChangeListener(listener);
    }
    
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.removePropertyChangeListener(listener);
    }
    
}
