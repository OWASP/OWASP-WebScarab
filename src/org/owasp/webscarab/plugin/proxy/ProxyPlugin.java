/*
 * ProxyPlugin.java
 *
 * Created on July 10, 2003, 12:41 PM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.httpclient.HTTPClient;

/**
 *
 * @author  rdawes
 */
public abstract class ProxyPlugin {
    
    public void setModel(SiteModel model, String type, Object connection) {
    }
    
    public void flush() throws StoreException {
    }
    
    /** The plugin name
     * @return The name of the plugin
     */
    public abstract String getPluginName();
    
    public abstract HTTPClient getProxyPlugin(HTTPClient in);
    
}
