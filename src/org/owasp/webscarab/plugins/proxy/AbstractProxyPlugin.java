/*
 * AbstractProxyPlugin.java
 *
 * Created on July 27, 2003, 6:09 PM
 */

package org.owasp.webscarab.plugins.proxy;

import org.owasp.webscarab.model.*;
import java.io.IOException;
import java.util.Properties;

/**
 *
 * @author  rdawes
 */
abstract public class AbstractProxyPlugin implements ProxyPlugin {
    
    /** Creates a new instance of AbstractProxyPlugin */
    public AbstractProxyPlugin() {
    }
    
    public Request interceptRequest(Request request) throws IOException {
        return request;
    }
    
    public Response interceptResponse(Request request, Response response) throws IOException {
        return response;
    }
    
    public void setProperties(Properties properties) {
    }
    
    protected String _dir;
    
    /** called to create any directory structures required by this plugin.
     * @param dir a String representing the base directory under which this session's 
     * data will be saved
     */    
    public void initDirectory(String dir) {
        _dir = dir;
    }
    
    /** Instructs the plugin to discard any session specific data that it may hold */
    public void discardSessionData() {
    }
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void saveSessionData(String dir) {
        _dir = dir;
    }
    
    /** called to instruct the plugin to read any saved state data from the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void loadSessionData(String dir) {
        _dir = dir;
    }
    
}
