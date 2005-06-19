/*
 * Search.java
 *
 * Created on 19 June 2005, 01:40
 */

package org.owasp.webscarab.plugin.search;

import org.owasp.webscarab.model.*;
import org.owasp.webscarab.plugin.*;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.logging.Logger;

import bsh.Interpreter;
import bsh.EvalError;
import bsh.TargetError;

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
    }
    
    public SearchModel getModel() {
        return _model;
    }
    
    public void addSearch(String description, String expression) {
        _model.addSearch(description, expression);
    }
    
    public void removeSearch(String description) {
        _model.removeSearch(description);
    }
    
    public void setFilter(String description) {
        _model.setFilter(description);
    }
    
    public void reload(String description) {
        ConversationID id = null;
        try {
            String expr = _model.getSearchExpression(description);
            ConversationModel cmodel = _framework.getModel().getConversationModel();
            int count = cmodel.getConversationCount(null);
            for (int i=0; i<count; i++) {
                id = cmodel.getConversationAt(null, i);
                _logger.info("Checking conversation " + id);
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
    
    private boolean matches(ConversationID id, Request request, Response response, String origin, String expression) throws TargetError, EvalError {
        _interpreter.set("frameworkModel", _frameworkModel);
        _interpreter.set("id", id);
        _interpreter.set("request", request);
        _interpreter.set("response", response);
        _interpreter.set("origin", origin);
        Object result = _interpreter.eval(expression);
        if (result != null && result instanceof Boolean) {
            boolean b = ((Boolean)result).booleanValue();
            _logger.info("Got " + b);
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
                        }
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
