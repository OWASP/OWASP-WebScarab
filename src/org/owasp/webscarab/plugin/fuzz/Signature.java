/*
 * Signature.java
 *
 * Created on 23 February 2005, 08:30
 */

package org.owasp.webscarab.plugin.fuzz;

import java.net.MalformedURLException;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.HttpUrl;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import java.net.MalformedURLException;

/**
 *
 * @author  rogan
 */
public class Signature {
    
    private static Parameter[] NONE = new Parameter[0];
    
    private String _method;
    private HttpUrl _url;
    private String _contentType;
    private Parameter[] _parameters;
    
    /** Creates a new instance of Signature */
    public Signature(Request request) {
        _method = request.getMethod();
        _url = request.getURL();
        if (_url.getParameters() != null) _url = _url.getParentUrl();
        _contentType = request.getHeader("Content-Type");
        _parameters = Parameter.getParameters(request);
    }
    
    public Signature(String signature) throws MalformedURLException {
        String[] parts = signature.split(" ");
        _method = parts[0];
        _url = new HttpUrl(parts[1]);
        _contentType = parts[2].substring(1, parts[2].length()-1);
        if (_contentType.equals("null")) 
            _contentType = null;
        List parameters = new ArrayList();
        for (int i=3; i<parts.length; i++) {
            int colon = parts[i].indexOf(":");
            String location = parts[i].substring(0, colon);
            int left = parts[i].indexOf('(', colon);
            String name = parts[i].substring(colon+1, left);
            String type = parts[i].substring(left+1, parts[i].length()-1);
            Parameter param = new Parameter(location, name, type, "");
            parameters.add(param);
        }
        _parameters = (Parameter[]) parameters.toArray(Parameter.NO_PARAMS);
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
    
    public Parameter[] getParameters() {
        return _parameters;
    }
    
    public String toString() {
        StringBuffer buff = new StringBuffer();
        buff.append(_method).append(" ").append(_url).append(" ");
        buff.append("(").append(_contentType).append(")");
        for (int i=0; i<_parameters.length; i++) {
            buff.append(" ").append(_parameters[i].getLocation()).append(":").append(_parameters[i].getName());
            buff.append("(").append(_parameters[i].getType()).append(")");
        }
        return buff.toString();
    }
    
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Signature)) return false;
        Signature that = (Signature) obj;
        if (!_method.equals(that._method)) return false;
        if (!_url.equals(that._url)) return false;
        if (_contentType == null && that._contentType != null) return false;
        if (_contentType != null && that._contentType == null) return false;
        if (_contentType != null && !_contentType.equals(that._contentType)) return false;
        if (_parameters.length != that._parameters.length) return false;
        for (int i=0; i<_parameters.length; i++) {
            if (! _parameters[i].equals(that._parameters[i])) return false;
        }
        return true;
    }
    
}
