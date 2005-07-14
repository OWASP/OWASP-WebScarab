/*
 * ScriptManager.java
 *
 * Created on 07 January 2005, 04:42
 */

package org.owasp.webscarab.plugin;

import org.apache.bsf.BSFManager;
import org.apache.bsf.BSFException;
import org.apache.bsf.BSFEngine;

import java.util.Vector;

import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rogan
 */
public class ScriptManager {
    
    private BSFManager _bsfManager;
    private TreeMap _hooks = new TreeMap();
    private EventListenerList _listeners = new EventListenerList();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ScriptManager */
    public ScriptManager(Framework framework) {
        try {
            _bsfManager = new BSFManager();
            // _bsfManager.declareBean("framework", framework, framework.getClass());
            _bsfManager.declareBean("out", System.out, System.out.getClass());
            _bsfManager.declareBean("err", System.err, System.out.getClass());
        } catch (BSFException bsfe) {
            _logger.severe("Declaring a bean should not throw an exception! " + bsfe);
        }
    }
    
    public void addScriptListener(ScriptListener listener) {
        synchronized(_listeners) {
            _listeners.add(ScriptListener.class, listener);
        }
    }
    
    public void removeScriptListener(ScriptListener listener) {
        synchronized(_listeners) {
            _listeners.remove(ScriptListener.class, listener);
        }
    }
    
    public void registerHooks(String pluginName, Hook[] hooks) {
        if (hooks != null && hooks.length > 0) {
            _hooks.put(pluginName, hooks);
            for (int i=0; i<hooks.length; i++) {
                hooks[i].setBSFManager(_bsfManager);
                hooks[i].setScriptManager(this);
            }
            fireHooksChanged();
        }
    }
    
    public int getPluginCount() {
        return _hooks.size();
    }
    
    public String getPlugin(int i) {
        String[] plugins = (String[]) _hooks.keySet().toArray(new String[0]);
        return plugins[i];
    }
    
    public int getHookCount(String plugin) {
        Hook[] hooks = (Hook[]) _hooks.get(plugin);
        if (hooks == null) return 0;
        return hooks.length;
    }
    
    public Hook getHook(String plugin, int i) {
        Hook[] hooks = (Hook[]) _hooks.get(plugin);
        if (hooks == null) return null;
        return hooks[i];
    }
    
    public void addScript(String plugin, Hook hook, Script script, int position) {
        try { 
            String language = BSFManager.getLangFromFilename(script.getFile().getName());
            if (language != null) {
                script.setLanguage(language);
                script.setEnabled(true);
                hook.addScript(script, position);
                fireScriptAdded(plugin, hook, script);
            }
        } catch (BSFException bsfe) {
            _logger.warning("Language not supported " + bsfe);
        }
    }
    
    public void addScript(String plugin, Hook hook, Script script) {
        addScript(plugin, hook, script, hook.getScriptCount());
    }
    
    public void setEnabled(String plugin, Hook hook, Script script, boolean enabled) {
        script.setEnabled(enabled);
        fireScriptChanged(plugin, hook, script);
    }
    
    public void removeScript(String plugin, Hook hook, Script script) {
        int count = hook.getScriptCount();
        for (int i=0; i<count; i++) {
            Script s = hook.getScript(i);
            if (s == script) {
                hook.removeScript(i);
                fireScriptRemoved(plugin, hook, script);
                return;
            }
        }
    }
    
    /**
     * tells listeners that a new Hook has been added
     * @param hook the hook
     */
    protected void fireHooksChanged() {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).hooksChanged();
            }
        }
    }
    
    /**
     * tells listeners that a script has been added
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptAdded(String plugin, Hook hook, Script script) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptAdded(plugin, hook, script);
            }
        }
    }
    
    /**
     * tells listeners that a script has been removed
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptRemoved(String plugin, Hook hook, Script script) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptRemoved(plugin, hook, script);
            }
        }
    }
    
    /**
     * tells listeners that execution of a Script has begun
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptStarted(String plugin, Hook hook, Script script) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptStarted(plugin, hook, script);
            }
        }
    }
    
    /**
     * tells listeners that execution of a Script has ended
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptEnded(String plugin, Hook hook, Script script) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptEnded(plugin, hook, script);
            }
        }
    }
    
    /**
     * tells listeners that a Script has changed
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptChanged(String plugin, Hook hook, Script script) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptChanged(plugin, hook, script);
            }
        }
    }
    
    /**
     * tells listeners that execution of a Script resulted in an error
     * @param hook the hook
     * @param script the script
     */
    protected void fireScriptError(String plugin, Hook hook, Script script, Throwable error) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).scriptError(plugin, hook, script, error);
            }
        }
    }
    
    /**
     * tells listeners that execution of a Hook has ended
     * @param hook the hook
     */
    protected void fireHookEnded(String plugin, Hook hook) {
        // Guaranteed to return a non-null array
        Object[] listeners = _listeners.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==ScriptListener.class) {
                ((ScriptListener)listeners[i+1]).hookEnded(plugin, hook);
            }
        }
    }
    
}
