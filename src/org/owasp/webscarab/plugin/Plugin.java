/*
 * WebScarabPlugin.java
 *
 * Created on July 10, 2003, 12:21 PM
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.model.SiteModel;

/**
 * This abstract class lists the basics that a WebScarab plugin will need to provide
 * @author rdawes
 */
public abstract class Plugin implements Runnable {
    
    /**
     * indicates whether the plugin is running or not
     */    
    protected boolean _running = false;
    
    /**
     * informs the plugin that the Site Model has changed
     * @param model the new model
     */    
    public abstract void setSession(SiteModel model, String type, Object connection) throws StoreException;
    
    /** The plugin name
     * @return The name of the plugin
     */    
    public abstract String getPluginName();
    
    /**
     * called to instruct the plugin to flush any memory-only state to the store.
     * @throws StoreException if there is any problem saving the session data
     */    
    public abstract void flush() throws StoreException;
    
    public boolean isRunning() {
        return _running;
    }
    
    /** called to test whether the plugin is able to be stopped
     * @return false if the plugin can be stopped
     */
    public abstract boolean isBusy();
    
    /** called to determine what the current status of the plugin is
     */
    public abstract String getStatus();
    
    /**
     * starts the plugin running
     */
    public abstract void run();
    
    /**
     * called to suspend or stop the plugin
     */
    public abstract boolean stop();
    
}
