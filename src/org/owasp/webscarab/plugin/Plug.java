/*
 * WebScarab.java
 *
 * Created on July 13, 2003, 8:25 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.CookieJar;

import java.util.Properties;

/**
 *
 * @author  rdawes
 */
public interface Plug {
    
    void addPlugin( WebScarabPlugin plugin );
    
    String addConversation( String origin, Request request, Response response );

    CookieJar getCookieJar();
}
