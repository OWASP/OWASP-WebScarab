/*
 * Scripted.java
 *
 * Created on 03 January 2005, 09:33
 */

package org.owasp.webscarab.plugin.scripted;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;

import org.apache.bsf.BSFManager;
import org.apache.bsf.BSFException;

import java.util.logging.Logger;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.PrintStream;

/**
 *
 * @author  rogan
 */
public class Scripted implements Plugin {
    
    private Framework _framework;
    private ScriptedUI _ui = null;
    
    private String _script = null;
    private String _scriptLanguage = null;
    
    private BSFManager _bsfManager = new BSFManager();
    private Thread _pluginThread = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private boolean _running = false;
    private boolean _stopping = false;
    
    private boolean _runScript = false;
    
    private String _status = "Stopped";
    
    private Object _lock = new Object();
    
    private ScriptedObjectModel _som;
    private PrintStream _out = System.out;
    private PrintStream _err = System.err;
    
    /** Creates a new instance of Scripted */
    public Scripted(Framework framework) {
        _framework = framework;
        _som = new ScriptedObjectModel(_framework);
        try {
            InputStream is = null;
            String defaultScript = Preferences.getPreference("Scripted.script");
            String language;
            if (defaultScript != null && !defaultScript.equals("")) {
                is = new FileInputStream(defaultScript);
                language = _bsfManager.getLangFromFilename(defaultScript);
            } else {
                is = getClass().getResourceAsStream("script.bsh");
                language = "beanshell";
            }
            if (is == null) return;
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuffer script = new StringBuffer();
            while ((line = br.readLine()) != null) {
                script.append(line).append("\n");
            }
            setScriptLanguage(language);
            setScript(script.toString());
        } catch (Exception e) {
            _logger.warning("Error loading default script" + e);
        }
    }
    
    public void setUI(ScriptedUI ui) {
        _ui = ui;
        if (_ui != null) {
            _ui.setEnabled(isRunning());
            PrintStream ps = _ui.getOutputStream();
            if (ps != null) _out = ps;
            ps = _ui.getErrorStream();
            if (ps != null) _err = ps;
        } else {
            _out = System.out;
            _err = System.err;
        }
        
    }
    
    public void setScriptLanguage(String language) {
        _scriptLanguage = language;
    }
    
    public String getScriptLanguage() {
        return _scriptLanguage;
    }
    
    public void setScript(String script) {
        _script = script;
    }
    
    public String getScript() {
        return _script;
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        // we do no analysis in this plugin
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "Scripted";
    }
    
    public String getStatus() {
        return _status;
    }
    
    public boolean isBusy() {
        return false;
    }
    
    public boolean isModified() {
        return false;
    }
    
    public boolean isRunning() {
        return _running;
    }
    
    public void run() {
        _pluginThread = Thread.currentThread();
        _running = true;
        _stopping = false;
        while (! _stopping) {
            synchronized(_lock) {
                try {
                    _status = "Idle";
                    _lock.wait();
                } catch (InterruptedException ie) {
                    // interrupted by shutting down the plugin
                }
            }
            if (_runScript) {
                _runScript = false;
                if (_ui != null) _ui.scriptStarted();
                _status = "Running";
                try {
                    _bsfManager.declareBean("scripted", _som, _som.getClass());
                    _bsfManager.declareBean("out", _out, _out.getClass());
                    _bsfManager.declareBean("err", _err, _err.getClass());
                    _bsfManager.exec(_scriptLanguage, "Scripted", 0, 0, _script);
                } catch (BSFException bsfe) {
                    if (_ui != null) _ui.scriptError("Unknown reason", bsfe);
                // } catch (InterruptedException ie) {
                    // interrupted by the user
                }
                if (_ui != null) _ui.scriptStopped();
            }
        }
        _running = false;
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
        // we handle no persistent storage in this plugin
    }
    
    public boolean stop() {
        _running = false;
        stopScript();
        return ! _running;
    }
    
    public void stopScript() {
        if (_pluginThread != null && _pluginThread.isAlive()) 
            _pluginThread.interrupt();
    }
    
    public void runScript() {
        if (_scriptLanguage != null && _script != null) {
            _runScript = true;
            synchronized (_lock) {
                _lock.notifyAll();
            }
        }
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
}
