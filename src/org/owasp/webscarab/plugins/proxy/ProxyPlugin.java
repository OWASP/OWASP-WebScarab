/*
 * ProxyPlugin.java
 *
 * Created on July 10, 2003, 12:41 PM
 */

package src.org.owasp.webscarab.plugins.proxy;

import org.owasp.webscarab.model.*;
import java.util.Properties;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public interface ProxyPlugin {
    
    public String getPluginName();
    
    public Request interceptRequest(Request request) throws IOException;
    
    public Response interceptResponse(Request request, Response response) throws IOException;
    
    public void setProperties(Properties properties);
    
    /** called to create any directory structures required by this plugin.
     * @param dir a String representing the base directory under which this session's 
     * data will be saved
     */    
    public void initDirectory(String dir);
    
    /** Instructs the plugin to discard any session specific data that it may hold */
    public void discardSessionData();
    
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void saveSessionData(String dir);
    
    /** called to instruct the plugin to read any saved state data from the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     */    
    public void loadSessionData(String dir);
    
}
