/*
 * Extensions.java
 *
 * Created on 04 December 2005, 08:52
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.extensions;

import java.io.File;
import java.io.IOException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;

/**
 *
 * @author rdawes
 */
public class Extensions implements Plugin {
    
    private Framework _framework;
    private ExtensionsModel _model;
    
    /** Creates a new instance of Extensions */
    public Extensions(Framework framework) {
        _framework = framework;
        _model = new ExtensionsModel(framework.getModel());
    }

    public void analyse(ConversationID id, Request request, Response response, String origin) {
    }

    public void flush() throws StoreException {
    }

    public String getPluginName() {
        return "Extensions";
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
        // I actually suggest that you not make this plugin run in its
        // own thread. I'd like to move towards a caller-threaded approach
        // i.e. the caller provides a thread to run the checkExtensions* methods
        // and blocks until it returns (i.e. after the various URL's have been
        // checked, or we are interrupted somehow)
        _model.setRunning(true);
    }

    public void setSession(String type, Object store, String session) throws StoreException {
    }

    public boolean stop() {
        _model.setRunning(false);
        return _model.isRunning();
    }
    
    public void loadFileExtensions(File file) throws IOException {
        // convenience method, calls setFileExtensions . . . 
    }
    
    public void setFileExtensions(String[] extensions) {
    }
    
    // can't quite decide whether this should be in the model or not.
    // your thoughts?
    public String[] getFileExtensions() {
    }
    
    public void loadDirectoryExtensions(File file) throws IOException {
        // same as above
    }
    
    public void setDirectoryExtensions(String extensions) {
    }
    
    public String[] getDirectoryExtensions() {
    }
    
    public ExtensionsModel getModel() {
        // ExtensionsModel should have a getUrlModel() and a getConversationModel()
        // method, like FrameworkModel
    }
    
    public void checkExtensionsUnder(HttpUrl url) throws IOException {
        // I select an url, click check recursively
    }
    
    public void checkExtensionsFor(HttpUrl urls[]) throws IOException {
        // I select a bunch of URL's, click check THESE
    }
    
    public void stopChecks() {
        // Stop checks, let the other thread return ASAP
    }
    
}
