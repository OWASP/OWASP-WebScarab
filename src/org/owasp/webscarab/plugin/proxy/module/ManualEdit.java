/*
 * ManualEdit.java
 *
 * Created on July 10, 2003, 4:46 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

import java.util.Iterator;
import org.owasp.util.Prop;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.Preferences;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;
import org.owasp.webscarab.plugin.proxy.AbstractProxyPlugin;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ManualEdit extends AbstractProxyPlugin {

    private String includeRegex = "*";
    private String excludeRegex = "";
    private String[] interceptMethods = null;
    private boolean interceptRequest = false;
    private boolean interceptResponse = false;
    private ConversationEditor _ce = null;
    
    /** Creates a new instance of ManualEdit */
    public ManualEdit() {
        setDefaultProperty("ManualEdit.includeRegex",".*");
        setDefaultProperty("ManualEdit.excludeRegex",".*\\.(gif)|(jpg)|(css)|(js)$");
        setDefaultProperty("ManualEdit.interceptMethods","GET,POST");
        setDefaultProperty("ManualEdit.interceptRequest","false");
        setDefaultProperty("ManualEdit.interceptResponse","false");
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "ManualEdit.includeRegex";
        String value = _prop.getProperty(prop);
        if (value == null) value = "";
        setIncludeRegex(value);
        
        prop = "ManualEdit.excludeRegex";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setExcludeRegex(value);
        
        prop = "ManualEdit.interceptMethods";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setInterceptMethods(value.split(", *"));
            
        prop = "ManualEdit.interceptRequest";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setInterceptRequest(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
            
        prop = "ManualEdit.interceptResponse";
        value = _prop.getProperty(prop);
        if (value == null) value = "";
        setInterceptResponse(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Manual Edit");
    }
    
    public void setIncludeRegex(String regex) {
       includeRegex = regex;
       String prop = "ManualEdit.includeRegex";
       setProperty(prop,regex);
    }
    
    public String getIncludeRegex() {
        return includeRegex;
    }
    
    public void setExcludeRegex(String regex) {
       excludeRegex = regex;
       String prop = "ManualEdit.excludeRegex";
       setProperty(prop,regex);
    }
    
    public String getExcludeRegex() {
        return excludeRegex;
    }
    
    public void setInterceptMethods(String[] methods) {
       interceptMethods = methods;
       String value = "";
       if (methods.length>0) {
           value = methods[0];
           for (int i=1; i< methods.length; i++) {
               value = value + ", " + methods[i];
           }
       }
       String prop = "ManualEdit.interceptMethods";
       setProperty(prop,value);
    }
    
    public String[] getInterceptMethods() {
        return interceptMethods;
    }
    
    public void setInterceptRequest(boolean bool) {
       interceptRequest = bool;
       String prop = "ManualEdit.interceptRequest";
       setProperty(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptRequest() {
        return interceptRequest;
    }
    
    public void setInterceptResponse(boolean bool) {
       interceptResponse = bool;
       String prop = "ManualEdit.interceptResponse";
       setProperty(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptResponse() {
        return interceptResponse;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new ProxyPlugin(in);
    }
    
    public void setConversationEditor(ConversationEditor ce) {
        _ce = ce;
    }
    
    private class ProxyPlugin implements HTTPClient {
    
        private HTTPClient _in;
        
        public ProxyPlugin(HTTPClient in) {
            _in = in;
        }
        
        public Response fetchResponse(Request request) {
            if (interceptRequest) {
                String url = request.getURL().toString();
                if (! url.matches(excludeRegex) && url.matches(includeRegex)) {
                    String method = request.getMethod();
                    for (int i=0; i<interceptMethods.length; i++) {
                        if (method.equals(interceptMethods[i])) {
                            if (_ce != null) {
                                request.readContentStream();
                                request = _ce.editRequest(request);
                            }
                        }
                    }
                }
            }
            Response response = _in.fetchResponse(request);
            if (interceptResponse) {
                String contentType = response.getHeader("Content-Type");
                if (!contentType.matches("text/.*")) {
                    return response;
                }
                if (_ce != null) {
                    response.readContentStream();
                    response = _ce.editResponse(request, response);
                }
            }
            return response;
        }
        
    }
 
}
