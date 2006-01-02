/*
 * Authenticator.java
 *
 * Created on 21 June 2005, 09:28
 */

package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.HttpUrl;

/**
 *
 * @author  rogan
 */
public interface Authenticator {

    String getAuthenticationHeader(HttpUrl url, String challenge, String preferredCredentials);
    
    String getCredentials(HttpUrl url, String challenge);
    
}
