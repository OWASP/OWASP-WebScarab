/*
 * Scripted.java
 *
 * Created on 03 January 2005, 09:33
 */

package org.owasp.webscarab.plugin.scripted;

import java.util.ArrayList;
import java.util.List;
import org.owasp.webscarab.httpclient.ConversationHandler;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;

import org.owasp.webscarab.httpclient.FetcherQueue;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;

import org.apache.bsf.BSFManager;
import org.apache.bsf.BSFException;

import java.util.logging.Logger;

import java.io.File;
import java.io.Reader;
import java.io.Writer;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;

import java.io.PrintStream;

/**
 *
 * @author  rogan
 */
public class Scripted implements Plugin, ConversationHandler {
    
    private Framework _framework;
    private ScriptedUI _ui = null;
    
    private File _scriptFile = null;
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
    
    private int _threads = 4;
    private FetcherQueue _fetcherQueue = null;
    private List _responseQueue = new ArrayList();
    
    private PrintStream _out = System.out;
    private PrintStream _err = System.err;
    
    /** Creates a new instance of Scripted */
    public Scripted(Framework framework) {
        _framework = framework;
        _som = new ScriptedObjectModel(_framework, this);
        try {
            String defaultScript = Preferences.getPreference("Scripted.script");
            if (defaultScript != null && !defaultScript.equals("")) {
                loadScript(new File(defaultScript));
            } else {
                InputStream is = getClass().getResourceAsStream("script.bsh");
                String language = "beanshell";
                if (is == null) return;
                loadScript(language, new InputStreamReader(is));
            }
        } catch (IOException ioe) {
            _logger.warning("Error loading default script" + ioe.getMessage());
        }
    }
    
    public void setUI(ScriptedUI ui) {
        _ui = ui;
        if (_ui == null) {
            _out = System.out;
            _err = System.err;
        }
    }
    
    public void setOut(PrintStream out) {
        if (out != null) {
            _out = out;
        } else {
            _out = System.out;
        }
    }
    
    public void setErr(PrintStream err) {
        _err = err;
    }
    
    public void loadScript(File file) throws IOException {
        if (file == null) {
            _scriptFile = null;
            if (_ui != null) _ui.scriptFileChanged(file);
            setScript("", "");
            return;
        }
        String language = "Unknown";
        try {
            language = BSFManager.getLangFromFilename(file.getName());
        } catch (Throwable t) {}
        loadScript(language, new FileReader(file));
        _scriptFile = file;
        if (_ui != null) _ui.scriptFileChanged(file);
    }
    
    public void saveScript(File file) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(file));
        bw.write(_script);
        bw.close();
    }
    
    private void loadScript(String language, Reader reader) throws IOException {
        _scriptFile = null;
        setScript("", "");
        BufferedReader br = new BufferedReader(reader);
        String line;
        StringBuffer script = new StringBuffer();
        while ((line = br.readLine()) != null) {
            script.append(line).append("\n");
        }
        br.close();
        setScript(language, script.toString());
    }
    
    public File getScriptFile() {
        return _scriptFile;
    }
    
    public String getScriptLanguage() {
        return _scriptLanguage;
    }
    
    public String getScript() {
        return _script;
    }
    
    public void setScript(String language, String script) {
        _scriptLanguage = language;
        _script = script;
        if (_ui != null) {
            _ui.scriptLanguageChanged(language);
            _ui.scriptChanged(script);
        }
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
                _fetcherQueue = new FetcherQueue("Scripted", this, _threads, 0);
                try {
                    _bsfManager.declareBean("framework", _framework, _framework.getClass());
                    _bsfManager.declareBean("scripted", _som, _som.getClass());
                    _bsfManager.declareBean("out", _out, _out.getClass());
                    _bsfManager.declareBean("err", _err, _err.getClass());
                    _bsfManager.exec(_scriptLanguage, "Scripted", 0, 0, _script);
                } catch (BSFException bsfe) {
                    if (_ui != null) _ui.scriptError("Unknown reason", bsfe);
                }
		_fetcherQueue.stop();
		_fetcherQueue = null;
                synchronized(_responseQueue) {
                    _responseQueue.clear();
                }
                if (_ui != null) _ui.scriptStopped();
            }
        }
        _running = false;
    }
    
    Response fetchResponse(Request request) throws IOException {
        return HTTPClientFactory.getInstance().fetchResponse(request);
    }
    
    boolean hasAsyncCapacity() {
        return _fetcherQueue.getRequestsQueued() < _threads;
    }
    
    void submitAsyncRequest(Request request) {
        _fetcherQueue.submit(request);
    }
    
    boolean isAsyncBusy() {
        return _fetcherQueue.isBusy();
    }
    
    boolean hasAsyncResponse() {
        synchronized (_responseQueue) {
            return _responseQueue.size()>0;
        }
    }
    
    public void requestError(Request request, IOException ioe) {
        synchronized (_responseQueue) {
            _responseQueue.add(ioe);
            _responseQueue.notify();
        }
    }

    public void responseReceived(Response response) {
        synchronized (_responseQueue) {
            _responseQueue.add(response);
            _responseQueue.notify();
        }
    }
    
    Response getAsyncResponse() throws IOException {
        synchronized (_responseQueue) {
            while (_responseQueue.size() == 0) {
                try {
                    _responseQueue.wait();
                } catch (InterruptedException ie) {}
            }
            Object obj = _responseQueue.remove(0);
            if (obj instanceof Response) return (Response) obj;
            throw (IOException) obj;
        }
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
