/*
 * ManualEdit.java
 *
 * Created on July 10, 2003, 4:46 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;
import org.owasp.webscarab.plugin.proxy.AbstractProxyPlugin;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;

import java.util.logging.Logger;

import bsh.Interpreter;
import bsh.EvalError;

/**
 *
 * @author  rdawes
 */
public class BeanShell extends AbstractProxyPlugin {
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private String _scriptFile = "";
    private String _beanScript = "response = fetchResponse(request);";
    private boolean _enabled = false;
    
    /** Creates a new instance of ManualEdit */
    public BeanShell() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "BeanShell.scriptFile";
        String value = _prop.getProperty(prop);
        if (value == null) value = "";
        _scriptFile = value;
        if (!_scriptFile.equals("")) {
            loadScriptFile(_scriptFile);
        }
        
        prop = "BeanShell.enabled";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setEnabled(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Bean Shell");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "BeanShell.enabled";
        setProperty(prop,Boolean.toString(bool));
    }
    
    public boolean getEnabled() {
        return _enabled;
    }
    
    private void loadScriptFile(String filename) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            StringBuffer sb = new StringBuffer();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            setScript(sb.toString());
        } catch (Exception e) {
            _logger.severe("Error reading BeanShell script from '" + filename + "' : " + e);
            setScript("");
        }
    }
    
    public void setScriptFile(String filename) {
        _scriptFile = filename;
        String prop = "BeanShell.scriptfile";
        setProperty(prop,filename);
        if (!filename.equals("")) {
            loadScriptFile(filename);
        } else {
            setScript("");
        }
    }
    
    public String getScriptFile() {
        return _scriptFile;
    }
    
    public void setScript(String script) {
        _beanScript = script;
    }
    
    public String getScript() {
        return _beanScript;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new ProxyPlugin(in);
    }
    
    private class ProxyPlugin implements HTTPClient {
        
        private String _imports =
        "import org.owasp.webscarab.model.Request;\n" +
        "import org.owasp.webscarab.model.Response;";
        private String _fetchResponse =
        "Response fetchResponse(Request request) { \n" +
        "  return _in.fetchResponse(request); \n" +
        "}";
        private HTTPClient _in;
        private final String _script;
        
        public ProxyPlugin(HTTPClient in) {
            _in = in;
            _script = _beanScript;
        }
        
        public Response fetchResponse(Request request) throws IOException {
            if (_enabled) {
                try {
                    Interpreter interpreter = new Interpreter();
                    interpreter.set("_in", _in);
                    interpreter.eval(_imports);
                    interpreter.eval(_fetchResponse);
                    interpreter.set("request", request);
                    interpreter.eval(_script);
                    Response response = (Response) interpreter.get("response");
                    response.addHeader("X-BeanShell", "possibly modified");
                    return response;
                } catch (EvalError e) {
                    System.out.println("Error evaluating bean script : " + e);
                    return null;
                }
            } else {
                return _in.fetchResponse(request);
            }
        }
    }
    
}
