/*
 * ManualEdit.java
 *
 * Created on July 10, 2003, 4:46 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.util.logging.Logger;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public class ManualEdit extends ProxyPlugin {

    private String _includeRegex = "*";
    private String _excludeRegex = "";
    private String[] _interceptMethods = null;
    private boolean _interceptRequest = false;
    private boolean _interceptResponse = false;
    private ManualEditUI _ui = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ManualEdit */
    public ManualEdit() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "ManualEdit.includeRegex";
        String value = Preferences.getPreference(prop, ".*");
        _includeRegex = value;
        
        prop = "ManualEdit.excludeRegex";
        value = Preferences.getPreference(prop, ".*\\.(gif)|(jpg)|(css)|(js)$");
        _excludeRegex= value;
        
        prop = "ManualEdit.interceptMethods";
        value = Preferences.getPreference(prop, "GET, POST");
        _interceptMethods = value.split(" *, *");
            
        prop = "ManualEdit.interceptRequest";
        value = Preferences.getPreference(prop, "false");
        _interceptRequest = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
            
        prop = "ManualEdit.interceptResponse";
        value = Preferences.getPreference(prop, "false");
        _interceptResponse = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
    }
    
    public String getPluginName() {
        return new String("Manual Edit");
    }
    
    public void setUI(ManualEditUI ui) {
        _ui = ui;
    }
    
    public void setIncludeRegex(String regex) {
       _includeRegex = regex;
       String prop = "ManualEdit.includeRegex";
       Preferences.setPreference(prop,regex);
    }
    
    public String getIncludeRegex() {
        return _includeRegex;
    }
    
    public void setExcludeRegex(String regex) {
       _excludeRegex = regex;
       String prop = "ManualEdit.excludeRegex";
       Preferences.setPreference(prop,regex);
    }
    
    public String getExcludeRegex() {
        return _excludeRegex;
    }
    
    public void setInterceptMethods(String[] methods) {
       _interceptMethods = methods;
       String value = "";
       if (methods.length>0) {
           value = methods[0];
           for (int i=1; i< methods.length; i++) {
               value = value + ", " + methods[i];
           }
       }
       String prop = "ManualEdit.interceptMethods";
       Preferences.setPreference(prop,value);
    }
    
    public String[] getInterceptMethods() {
        return _interceptMethods;
    }
    
    public void setInterceptRequest(boolean bool) {
       _interceptRequest = bool;
       String prop = "ManualEdit.interceptRequest";
       Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptRequest() {
        return _interceptRequest;
    }
    
    public void setInterceptResponse(boolean bool) {
       _interceptResponse = bool;
       String prop = "ManualEdit.interceptResponse";
       Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptResponse() {
        return _interceptResponse;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new Plugin(in);
    }
    
    private class Plugin implements HTTPClient {
    
        private HTTPClient _in;
        
        public Plugin(HTTPClient in) {
            _in = in;
        }
        
        public Response fetchResponse(Request request) throws IOException {
            if (_interceptRequest) {
                String url = request.getURL().toString();
                if (! url.matches(_excludeRegex) && url.matches(_includeRegex)) {
                    String method = request.getMethod();
                    for (int i=0; i<_interceptMethods.length; i++) {
                        if (method.equals(_interceptMethods[i])) {
                            if (_ui != null) {
                                request = _ui.editRequest(request);
                                if (request == null) 
                                    throw new IOException("Request aborted in Manual Edit");
                            }
                        }
                    }
                }
            }
            Response response = _in.fetchResponse(request);
            if (_interceptResponse) {
                String contentType = response.getHeader("Content-Type");
                if (contentType == null || ! contentType.matches("text/.*")) {
                    return response;
                }
                if (_ui != null) {
                    request = response.getRequest();
                    response = _ui.editResponse(request, response);
                    if (response == null) throw new IOException("Response aborted in Manual Edit");
                    if (response.getRequest() == null) response.setRequest(request);
                    response.addHeader("X-ManualEdit", "possibly modified");
                }
            }
            return response;
        }
        
    }
 
}
