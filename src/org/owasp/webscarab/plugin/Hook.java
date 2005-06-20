/*
 * Hook.java
 *
 * Created on 07 January 2005, 05:19
 */

package org.owasp.webscarab.plugin;

import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

import org.apache.bsf.BSFManager;
import org.apache.bsf.BSFException;

/**
 *
 * @author  rogan
 */
public class Hook {
    
    private String _name;
    private String _description;
    private List _scripts = new ArrayList();
    protected BSFManager _bsfManager = null;
    private ScriptManager _scriptManager = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of Hook */
    public Hook(String name, String description) {
        _name = name;
        _description = description;
    }
    
    public void setBSFManager(BSFManager bsfManager) {
        _bsfManager = bsfManager;
    }
    
    public void setScriptManager(ScriptManager scriptManager) {
        _scriptManager = scriptManager;
    }
    
    protected void runScripts() {
        if (_bsfManager == null) return;
        synchronized(_bsfManager) {
            for (int i=0; i<_scripts.size(); i++) {
                Script script = (Script) _scripts.get(i);
                if (script.isEnabled()) {
//                    if (_scriptManager != null) _scriptManager.scriptStarted(this, script);
                    try {
                        _bsfManager.exec(script.getLanguage(), _name, 0, 0, script.getScript());
                    } catch (BSFException bsfe) {
                        _logger.warning("Script exception: " + bsfe);
//                        if (_scriptManager != null) _scriptManager.scriptError(this, script, bsfe);
                    }
//                    if (_scriptManager != null) _scriptManager.scriptEnded(this, script);
                }
            }
        }
    }
    
    public String getName() {
        return _name;
    }
    
    public String getDescription() {
        return _description;
    }
    
    public int getScriptCount() {
        return _scripts.size();
    }
    
    public Script getScript(int i) {
        return (Script) _scripts.get(i);
    }
    
    public void addScript(Script script) {
        _scripts.add(script);
    }
    
    public void addScript(Script script, int position) {
        _scripts.add(position, script);
    }
    
    public Script removeScript(int position) {
        return (Script)_scripts.remove(position);
    }
    
}
