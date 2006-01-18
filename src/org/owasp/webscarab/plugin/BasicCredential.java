/*
 * BasicCredential.java
 *
 * Created on 04 January 2006, 09:20
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin;

/**
 *
 * @author rdawes
 */
public class BasicCredential {
    
    private String _host;
    private String _realm;
    private String _username;
    private String _password;
    
    /**
     * Creates a new instance of BasicCredential 
     */
    public BasicCredential(String host, String realm, String username, String password) {
        _host = host;
        _realm = realm;
        _username = username;
        _password = password;
    }
    
    public String getHost() {
        return _host;
    }
    
    public String getRealm() {
        return _realm;
    }
    
    public String getUsername() {
        return _username;
    }
    
    public String getPassword() {
        return _password;
    }
    
}
