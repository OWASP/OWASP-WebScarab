/*
 * Signature.java
 *
 * Created on 23 February 2005, 08:30
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.model.HttpUrl;
import java.util.ArrayList;

/**
 *
 * @author  rogan
 */
public class Signature {
    
    private static Parameter[] NONE = new Parameter[0];
    
    String _method;
    HttpUrl _url;
    String _contentType;
    ArrayList _parameters;
    
    /** Creates a new instance of Signature */
    public Signature(String method, HttpUrl url, String contentType) {
        _method = method;
        _url = url;
        _contentType = contentType;
        _parameters = new ArrayList();
    }
    
    public String getMethod() {
        return _method;
    }
    
    public HttpUrl getUrl() {
        return _url;
    }
    
    public String getContentType() {
        return _contentType;
    }
    
    void addParameter(Parameter parameter) {
        _parameters.add(parameter);
    }
    
    public Parameter[] getParameters() {
        return (Parameter[]) _parameters.toArray(NONE);
    }
    
    public String toString() {
        return _method + " " + _url.toString() + ":" + _contentType + " " + _parameters;
    }
    
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Signature)) return false;
        Signature that = (Signature) obj;
        if (!_method.equals(that._method)) return false;
        if (!_url.equals(that._url)) return false;
        if (_contentType == null && that._contentType != null) return false;
        if (_contentType != null && that._contentType == null) return false;
        if (_contentType != null && !_contentType.equals(that._contentType)) return false;
        if (_parameters.size() != that._parameters.size()) return false;
        for (int i=0; i<_parameters.size(); i++) {
            if (! _parameters.get(i).equals(that._parameters.get(i))) return false;
        }
        return true;
    }
    
}
