/*
 * AbstractPluginModel.java
 *
 * Created on 25 April 2005, 07:23
 */

package org.owasp.webscarab.plugin;

import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rogan
 */
public class AbstractPluginModel {
    
    private FrameworkModel _frameworkModel;
    
    protected EventListenerList _listenerList = new EventListenerList();
    private String _status = "Stopped";
    private boolean _running = false;
    private boolean _stopping = false;
    private boolean _modified = false;
    private boolean _busy = false;
    
    /** Creates a new instance of AbstractPluginModel */
    public AbstractPluginModel(FrameworkModel frameworkModel) {
        _frameworkModel = frameworkModel;
    }
    
    public void setStatus(String status) {
        _status = status;
    }
    
    public String getStatus() {
        return _status;
    }
    
    public void setRunning(boolean running) {
        _running = running;
    }
    
    public boolean isRunning() {
        return _running;
    }
    
    public void setStopping(boolean stopping) {
        _stopping = stopping;
    }
    
    public boolean isStopping() {
        return _stopping;
    }
    
    public void setModified(boolean modified) {
        _modified = modified;
    }
    
    public boolean isModified() {
        return _modified;
    }
    
    public void setBusy(boolean busy) {
        _busy = busy;
    }
    
    public boolean isBusy() {
        return _busy;
    }
    
    /**
     * adds a listener to the model
     * @param listener the listener to add
     */
    public void addModelListener(PluginListener listener) {
        synchronized(_listenerList) {
            _listenerList.add(PluginListener.class, listener);
        }
    }
    
    /**
     * removes a listener from the model
     * @param listener the listener to remove
     */
    public void removeModelListener(PluginListener listener) {
        synchronized(_listenerList) {
            _listenerList.remove(PluginListener.class, listener);
        }
    }
    
    protected void firePluginStatusChanged(String status) {
        // FIXME : implement this!
    }
    
    protected void firePluginRunStatusChanged(boolean running, boolean stopping) {
        // FIXME : implement this!
    }
    
    protected void fireModifiedStatusChanged(boolean modified) {
        // FIXME : implement this!
    }
    
}
