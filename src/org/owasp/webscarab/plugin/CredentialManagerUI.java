/*
 * CredentialManagerUI.java
 *
 * Created on 04 January 2006, 09:09
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author rdawes
 */
public interface CredentialManagerUI {
    
    void requestCredentials(String host, String[] challenges);
    
}
