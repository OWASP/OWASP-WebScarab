/*
 * WebScarabPlugin.java
 *
 * Created on July 10, 2003, 12:21 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.util.Prop;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;
import java.io.FileNotFoundException;

/** This interface describes the requirements that a WebScarab plugin must implement
 * @author rdawes
 */
public interface WebScarabPlugin {
    
    /** Configures the plugin, based on any properties read from a configuration file.
     * If any plugin specific properties were not set in the configuration file, copies
     * the default values into the supplied Properties class.
     * @param prop The properties read from a configuration file, or similar
     */    
    void setProp ( Prop prop );
    
    /** The plugin name
     * @return The name of the plugin
     */    
    String getPluginName();
    
    /** Called by the WebScarab data model once the {@link Response} has been parsed. It
     * is called for all Conversations seen by the model (submitted by all plugins, not
     * just this one).
     * Any information gathered by this module should also be summarised into the
     * supplied URLInfo, since only this analysis procedure will know how to do so!
     * @param request The Request that caused this analysis
     * @param response The Response that was received
     * @param conversation The parsed Conversation to be analysed.
     * @param urlinfo The class instance that contains the summarised information about this
     * particular URL
     * @param parsed A parsed representation of the Response content. Check to see if this is a type
     * that you recognise, e.g. NodeList for HTML content
     */    
    void analyse(Request request, Response response, Conversation conversation, URLInfo urlinfo, Object parsed);
    
    /** called to create any directory structures required by this plugin.
     * @param dir a String representing the base directory under which this session's
     * data will be saved
     * @throws FileNotFoundException if there is any problem creating the initial structure
     */    
    void initDirectory(String dir) throws FileNotFoundException;
    
    /** Instructs the plugin to discard any session specific data that it may hold */
    void discardSessionData();
   
    /** called to instruct the plugin to save its current state to the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     * @throws FileNotFoundException if there is any problem saving the session data
     */    
    void saveSessionData(String dir) throws FileNotFoundException;
    
    /** called to instruct the plugin to read any saved state data from the specified directory.
     * @param dir a String representing the base directory under which this plugin can save its data
     * @throws FileNotFoundException if there is any problem reading the session data
     */    
    void loadSessionData(String dir) throws FileNotFoundException;
    
}
