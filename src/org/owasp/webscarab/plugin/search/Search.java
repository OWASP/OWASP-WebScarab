/*
 * Search.java
 *
 * Created on 19 June 2005, 01:40
 */

package org.owasp.webscarab.plugin.search;

import bsh.EvalError;
import bsh.Interpreter;
import bsh.TargetError;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;

import java.util.logging.Logger;

/**
 *
 * @author  rogan
 */
public class Search implements Plugin {
    
    private Framework _framework;
    private FrameworkModel _frameworkModel;
    private Interpreter _interpreter = new Interpreter();
    
    private SearchModel _model;
    
    private Thread _runThread;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of Search */
    public Search(Framework framework) {
        _framework = framework;
        _frameworkModel = _framework.getModel();
        _model = new SearchModel(_frameworkModel);
        loadSearches();
    }
    
    public SearchModel getModel() {
        return _model;
    }
    
    private void loadSearches() {
        String base="Search.";
        String description;
        String expression;
        int i=0;
        do {
            description=Preferences.getPreference(base+i+".description");
            expression=Preferences.getPreference(base+i+".expression");
            if (description != null && expression != null) {
                _model.addSearch(description, expression);
            }
            i++;
        } while (description != null );
    }
    
    private void saveSearches() {
        String base = "Search.";
        String[] searches = _model.getSearches();
        for (int i=0; i<searches.length; i++) {
            String expression = _model.getSearchExpression(searches[i]);
            Preferences.setPreference(base+i+".description", searches[i]);
            Preferences.setPreference(base+i+".expression", expression);
        }
        Preferences.remove(base+searches.length+".description");
        Preferences.remove(base+searches.length+".expression");
    }
    
    public void addSearch(String description, String expression) {
        _model.addSearch(description, expression);
        saveSearches();
    }
    
    public void removeSearch(String description) {
        _model.removeSearch(description);
        ConversationModel cmodel = _frameworkModel.getConversationModel();
        int count = cmodel.getConversationCount();
        for (int i=0; i<count; i++) {
            ConversationID id = cmodel.getConversationAt(i);
            _model.setSearchMatch(id, description, false);
        }
        saveSearches();
    }
    
    public void setFilter(String description) {
        _model.setFilter(description);
    }
    
    public void reload(String description) {
        ConversationID id = null;
        try {
            String expr = _model.getSearchExpression(description);
            ConversationModel cmodel = _frameworkModel.getConversationModel();
            int count = cmodel.getConversationCount();
            for (int i=0; i<count; i++) {
                id = cmodel.getConversationAt(i);
                Request request = cmodel.getRequest(id);
                Response response = cmodel.getResponse(id);
                String origin = cmodel.getConversationOrigin(id);
                boolean matches = matches(id, request, response, origin, expr);
                _model.setSearchMatch(id, description, matches);
            }
        } catch (Exception e) {
            _logger.warning("Evaluation error for conversation " + id + " : " + e.getMessage());
        }
    }
    
    private boolean matches(ConversationID id, Request request, Response response, String origin, String expression) throws EvalError {
        _interpreter.set("frameworkModel", _frameworkModel);
        _interpreter.set("id", id);
        _interpreter.set("request", request);
        _interpreter.set("response", response);
        _interpreter.set("origin", origin);
        Object result = _interpreter.eval(expression);
        if (result != null && result instanceof Boolean) {
            boolean b = ((Boolean)result).booleanValue();
            return b;
        } else {
            _logger.info("Got a " + result);
            return false;
        }
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        try {
            _model.readLock().acquire();
            synchronized(_interpreter) {
                String[] searches = _model.getSearches();
                for (int i=0; i<searches.length; i++) {
                    try {
                        String expression = _model.getSearchExpression(searches[i]);
                        boolean matches = matches(id, request, response, origin, expression);
                        if (matches) {
                            _model.setSearchMatch(id, searches[i], true);
                        } // no point unsetting if false, could not be set yet
                    } catch (TargetError te) {
                        _logger.warning("Evaluation error for conversation " + id + " : " + te.getMessage());
                    }
                }
            }
            _model.readLock().release();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "Search";
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
        _runThread = Thread.currentThread();
        _model.setStopping(false);
        _model.setRunning(true);
        _model.setStatus("Idle");
        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException ie) {}
        _model.setRunning(false);
        _model.setStatus("Stopped");
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
    }
    
    public boolean stop() {
        _runThread.interrupt();
        return true;
    }
    
}
