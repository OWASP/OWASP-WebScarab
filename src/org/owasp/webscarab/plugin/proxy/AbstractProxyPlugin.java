/*
 * AbstractProxyPlugin.java
 *
 * Created on July 27, 2003, 6:09 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

/**
 *
 * @author  rdawes
 */
abstract public class AbstractProxyPlugin 
	extends AbstractWebScarabPlugin
	implements ProxyPlugin
{
    
    /** Creates a new instance of AbstractProxyPlugin */
    public AbstractProxyPlugin() {
    }
    
    public Request interceptRequest(Request request) throws IOException {
        return request;
    }
    
    public Response interceptResponse(Request request, Response response) throws IOException {
        return response;
    }
    
}
