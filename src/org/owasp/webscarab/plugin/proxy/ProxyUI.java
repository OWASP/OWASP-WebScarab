/*
 * ProxyUI.java
 *
 * Created on July 20, 2004, 4:40 PM
 */

package org.owasp.webscarab.plugin.proxy;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.plugin.PluginUI;

/**
 *
 * @author  knoppix
 */
public interface ProxyUI extends PluginUI {
    
    void proxyAdded(String key);
    
    void proxyStarted(String key);
    
    void proxyStopped(String key);
    
    void proxyRemoved(String key);
    
    void requested(ConversationID id, String method, HttpUrl url);
    
    void received(ConversationID id, String status);
    
    void aborted(ConversationID id, String reason);
    
}
