/*
 * ProxyPlugin.java
 *
 * Created on July 10, 2003, 12:41 PM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.WebScarabPlugin;
import org.owasp.webscarab.httpclient.HTTPClient;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public interface ProxyPlugin
	extends WebScarabPlugin
{
    
    HTTPClient getProxyPlugin(HTTPClient in);
    
}
