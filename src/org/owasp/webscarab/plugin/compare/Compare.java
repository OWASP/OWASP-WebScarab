/*
 * Compare.java
 *
 * Created on 18 May 2005, 05:33
 */

package org.owasp.webscarab.plugin.compare;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Hook;

/**
 *
 * @author  rogan
 */
public class Compare implements Plugin {
    
    private CompareModel _model;
    
    /** Creates a new instance of Compare */
    public Compare(Framework framework) {
        _model = new CompareModel(framework.getModel());
    }
    
    public CompareModel getModel() {
        return _model;
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "Compare";
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isBusy() {
        return _model.isBusy();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public void run() {
        _model.setRunning(true);
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
    }
    
    public boolean stop() {
        _model.setRunning(false);
        return ! _model.isRunning();
    }
    
}
