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

import bsh.Interpreter;
import bsh.EvalError;
import bsh.ParseException;
import bsh.TargetError;

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
public class Scripted extends Plugin {
    
    private Framework _framework;
    private ScriptedUI _ui = null;
    private Interpreter _interpreter = null;
    private String _script = "";
    private Executor _executor = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of Scripted */
    public Scripted(Framework framework) {
        _framework = framework;
        try {
            InputStream is = null;
            String defaultScript = Preferences.getPreference("Scripted.script");
            if (defaultScript != null && !defaultScript.equals("")) {
                is = new FileInputStream(defaultScript);
            } else {
                is = getClass().getResourceAsStream("script.bsh");
            }
            if (is == null) return;
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line;
            StringBuffer script = new StringBuffer();
            while ((line = br.readLine()) != null) {
                script.append(line).append("\n");
            }
            setScript(script.toString());
        } catch (Exception e) {
            _logger.warning("Error loading default script" + e);
        }
    }
    
    public void setUI(ScriptedUI ui) {
        _ui = ui;
        if (_ui != null) {
            _ui.setEnabled(isRunning());
            if (_interpreter != null) {
                PrintStream ps = _ui.getOutputStream();
                if (ps != null) _interpreter.setOut(ps);
                ps = _ui.getErrorStream();
                if (ps != null) _interpreter.setErr(ps);
            }
        }
        
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        if (_interpreter != null) {
            synchronized(_interpreter) {
                try {
                    _interpreter.set("id", id);
                    _interpreter.set("request", request);
                    _interpreter.set("response", response);
                    _interpreter.set("origin", origin);
                    _interpreter.eval("analyse(id, request, response, origin)");
                } catch (EvalError ee) {
                    if (_ui != null) {
                        _ui.scriptError(ee);
                    } else {
                        _logger.warning(ee.toString());
                    }
                }
            }
        }
    }
    
    public void flush() throws StoreException {
    }
    
    public String getPluginName() {
        return "Scripted";
    }
    
    public String getStatus() {
        return "Idle";
    }
    
    public boolean isBusy() {
        return false;
    }
    
    public boolean isModified() {
        return false;
    }
    
    public void run() {
        _running = true;
    }
    
    public void setSession(String type, Object session, String id) throws StoreException {
    }
    
    public boolean stop() {
        _running = false;
        return ! _running;
    }
    
    public void stopScript() {
        if (_executor != null) _executor.stopScript();
    }
    
    public String getScript() {
        return _script;
    }
    
    public void setScript(String script) throws EvalError {
        _script = script;
        _interpreter = new Interpreter();
        if (_ui != null) {
            PrintStream ps = _ui.getOutputStream();
            if (ps != null) _interpreter.setOut(ps);
            ps = _ui.getErrorStream();
            if (ps != null) _interpreter.setErr(ps);
        }
        try {
            _interpreter.eval(script);
        } catch (EvalError ee) {
            _interpreter = null;
            throw ee;
        }
    }
    
    public void execute(int threads, long delay) {
        if (_interpreter == null) return;
        _executor = new Executor(_interpreter, threads, delay);
        _executor.start();
    }
    
    public void pause() {
        if (_executor != null) _executor.pause();
    }
    
    public void resume() {
        if (_executor != null) _executor.restart();
    }
    
    private class Executor extends Thread {
        
        private Interpreter _int;
        private long _delay;
        private AsyncFetcher _fetcher;
        private boolean _stopped = false;
        private boolean _paused = false;
        
        public Executor(Interpreter interpreter, int threads, long delay) {
            _int = interpreter;
            _fetcher = new AsyncFetcher("Script", threads);
            _delay = delay;
        }
        
        public synchronized void pause() {
            _paused = true;
        }
        
        public synchronized void restart() {
            _paused = false;
            this.notify();
        }
        
        public void run() {
            _stopped = false;
            int i = 1;
            if (_ui != null) _ui.scriptStarted();
            try {
                while (!_stopped) {
                    boolean hasNext = ((Boolean) _int.eval("hasNext()")).booleanValue();
                    if (_delay <= 0) {
                        Thread.yield();
                    } else {
                        try {
                            Thread.sleep(_delay);
                        } catch (InterruptedException ie) {}
                    }
                    if (hasNext && _fetcher.hasCapacity()) {
                        Request request = (Request) _int.eval("next()");
                        _fetcher.submit(request);
                        if (_ui != null) _ui.iteration(i++);
                    }
                    if (_fetcher.hasResponse()) {
                        Response response = _fetcher.receive();
                        Request request = response.getRequest();
                        boolean add;
                        synchronized (_int) {
                            _int.set("request", request);
                            _int.set("response", response);
                            add = ((Boolean) _int.eval("addConversation(request, response)")).booleanValue();
                        }
                        if (add) _framework.addConversation(request, response, "Scripted");
                    }
                    synchronized(this) {
                        if (_paused) {
                            if (_ui != null) _ui.scriptPaused();
                            try {
                                wait();
                            } catch (InterruptedException ie) {}
                            if (_ui != null) _ui.scriptResumed();
                        }
                    }
                    if (!hasNext && !_fetcher.isBusy()) _stopped = true;
                }
            } catch (EvalError ee) {
                if (_ui != null) _ui.scriptError(ee);
            } catch (Exception e) {
                _logger.severe("Error processing the script: " + e);
            }
            if (_ui != null) _ui.scriptStopped();
        }
        
        public synchronized void stopScript() {
            _paused = false;
            _stopped = true;
            _executor.notify();
        }
        
    }
}
