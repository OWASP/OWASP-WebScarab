/*
 * ManualEdit.java
 *
 * Created on July 10, 2003, 4:46 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

import java.util.Iterator;
import org.owasp.util.Prop;

import org.owasp.webscarab.model.*;
import org.owasp.webscarab.plugin.proxy.AbstractProxyPlugin;

// this is not right. I guess we should define a callback interface for this, rather
import org.owasp.webscarab.ui.swing.proxy.ManualEditFrame;

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
    
    /** Creates a new instance of ManualEdit */
    public ManualEdit() {
        _prop.put("ManualEdit.includeRegex",".*");
        _prop.put("ManualEdit.excludeRegex",".*\\.(gif)|(jpg)|(css)|(js)$");
        _prop.put("ManualEdit.interceptMethods","GET,POST");
        _prop.put("ManualEdit.interceptRequest","false");
        _prop.put("ManualEdit.interceptResponse","false");
        configure();
    }
    
    public void configure() {
        String prop = "ManualEdit.includeRegex";
        String value = _prop.get(prop);
        if (value == null) value = "";
        setIncludeRegex(value);
        
        prop = "ManualEdit.excludeRegex";
        value = _prop.get(prop);
        if (value == null) value = "";
        setExcludeRegex(value);
        
        prop = "ManualEdit.interceptMethods";
        value = _prop.get(prop);
        if (value == null) value = "";
        setInterceptMethods(value.split(", *"));
            
        prop = "ManualEdit.interceptRequest";
        value = _prop.get(prop);
        if (value == null) value = "";
        setInterceptRequest(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
            
        prop = "ManualEdit.interceptResponse";
        value = _prop.get(prop);
        if (value == null) value = "";
        setInterceptResponse(value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes"));
    }
    
    public String getPluginName() {
        return new String("Manual Edit");
    }
    
    public Request interceptRequest(Request request) throws IOException {
        System.out.println("In interceptRequest");
        if (interceptRequest) {
            String url = request.getURL().toString();
            if (url.matches(excludeRegex)) {
                System.out.println("Not editing - matches exclude");
                return request;
            }
            if (url.matches(includeRegex)) {
                String method = request.getMethod();
                for (int i=0; i<interceptMethods.length; i++) {
                    System.out.println("Comparing " + method + " and " + interceptMethods[i]);
                    if (method.equals(interceptMethods[i])) {
                        // FIXME : this should be done through an interface rather, and not
                        // instantiate new classes here.
                        ManualEditFrame mef = new ManualEditFrame();
                        mef.show();
                        request = mef.editRequest(request);
                        mef.dispose();
                        return request;
                    }
                }
                System.out.println("Did not match request method");
            }
        }
        System.out.println("Not set to intercept");
        return request;
    }
    
    public Response interceptResponse(Request request, Response response) throws IOException {
        if (interceptResponse) {
            String contentType = response.getHeader("Content-Type");
            if (!contentType.matches("text/.*")) {
                return response;
            }
            ManualEditFrame mef = new ManualEditFrame();
            mef.setRequest(request);
            mef.show();
            response = mef.editResponse(response);
            mef.dispose();
        }
        return response;
    }
    
    private void setProperty(String prop, String value) {
        String previous = _prop.get(prop);
        if (previous == null || !previous.equals(value)) {
            _prop.put(prop,value);
        }
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
    
}
