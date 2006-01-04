/*
 * DomainCredential.java
 *
 * Created on 04 January 2006, 09:23
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
public class DomainCredential {
    
    private String _host;
    private String _domain;
    private String _username;
    private String _password;
    
    /** Creates a new instance of DomainCredential */
    public DomainCredential(String host, String domain, String username, String password) {
        _host = host;
        _domain = domain;
        _username = username;
        _password = password;
    }
    
    public String getHost() {
        return _host;
    }
    
    public String getDomain() {
        return _domain;
    }
    
    public String getUsername() {
        return _username;
    }
    
    public String getPassword() {
        return _password;
    }
    
}
