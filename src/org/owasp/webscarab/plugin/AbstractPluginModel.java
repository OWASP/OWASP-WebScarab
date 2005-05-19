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

import java.beans.PropertyChangeSupport;
import java.beans.PropertyChangeListener;

/**
 *
 * @author  rogan
 */
public class AbstractPluginModel {
    
    private FrameworkModel _frameworkModel;
    private PropertyChangeSupport _changeSupport = new PropertyChangeSupport(this);
    
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
        if (!_status.equals(status)) {
            String old = _status;
            _status = status;
            _changeSupport.firePropertyChange("status", old, _status);
        }
    }
    
    public String getStatus() {
        return _status;
    }
    
    public void setRunning(boolean running) {
        if (_running != running) {
            _running = running;
            _changeSupport.firePropertyChange("running", !_running, _running);
        }
    }
    
    public boolean isRunning() {
        return _running;
    }
    
    public void setStopping(boolean stopping) {
        if (_stopping != stopping) {
            _stopping = stopping;
            _changeSupport.firePropertyChange("stopping", !_stopping, _stopping);
        }
    }
    
    public boolean isStopping() {
        return _stopping;
    }
    
    public void setModified(boolean modified) {
        if (_modified != modified) {
            _modified = modified;
            _changeSupport.firePropertyChange("modified", !_modified, _modified);
        }
    }
    
    public boolean isModified() {
        return _modified;
    }
    
    public void setBusy(boolean busy) {
        if (_busy != busy) {
            _busy = busy;
            _changeSupport.firePropertyChange("busy", !_busy, _busy);
        }
    }
    
    public boolean isBusy() {
        return _busy;
    }
    
    public void addPropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.addPropertyChangeListener(listener);
    }
    
    public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        _changeSupport.addPropertyChangeListener(propertyName, listener);
    }
    
    public void removePropertyChangeListener(PropertyChangeListener listener) {
        _changeSupport.removePropertyChangeListener(listener);
    }
    
    public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
        _changeSupport.removePropertyChangeListener(propertyName, listener);
    }
    
}
