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
    private List _parameters;
    
    /** Creates a new instance of Signature */
    public Signature(Request request) {
        _method = request.getMethod();
        _url = request.getURL();
        if (_url.getParameters() != null) _url = _url.getParentUrl();
        _contentType = request.getHeader("Content-Type");
        _parameters = parseParameters(request);
    }
    
    public Signature(String signature) throws MalformedURLException {
        String[] parts = signature.split(" ");
        _method = parts[0];
        _url = new HttpUrl(parts[1]);
        _contentType = parts[2].substring(1, parts[2].length()-1);
        if (_contentType.equals("null")) 
            _contentType = null;
        _parameters = new ArrayList();
        for (int i=3; i<parts.length; i++) {
            int colon = parts[i].indexOf(":");
            String location = parts[i].substring(0, colon);
            int left = parts[i].indexOf('(', colon);
            String name = parts[i].substring(colon+1, left);
            String type = parts[i].substring(left+1, parts[i].length()-1);
            Parameter param = new Parameter(location, name, type);
            _parameters.add(param);
        }
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
        return (Parameter[]) _parameters.toArray(NONE);
    }
    
    public String toString() {
        StringBuffer buff = new StringBuffer();
        buff.append(_method).append(" ").append(_url).append(" ");
        buff.append("(").append(_contentType).append(")");
        Iterator it = _parameters.iterator();
        while (it.hasNext()) {
            Parameter param = (Parameter) it.next();
            buff.append(" ").append(param.getLocation()).append(":").append(param.getName());
            buff.append("(").append(param.getType()).append(")");
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
        if (_parameters.size() != that._parameters.size()) return false;
        for (int i=0; i<_parameters.size(); i++) {
            if (! _parameters.get(i).equals(that._parameters.get(i))) return false;
        }
        return true;
    }
    
    private List parseParameters(Request request) {
        List params = new ArrayList();
        HttpUrl url = request.getURL();
        String fragment = url.getFragment();
        if (fragment != null) {
            NamedValue[] nv = NamedValue.splitNamedValues(fragment, "&", "=");
            for (int i=0; i<nv.length; i++) {
                if (nv[i] != null) {
                    Parameter param = new Parameter(Parameter.LOCATION_FRAGMENT, nv[i].getName(), "String");
                    params.add(param);
                }
            }
        }
        String query = url.getQuery();
        if (query != null) {
            NamedValue[] nv = NamedValue.splitNamedValues(query, "&", "=");
            for (int i=0; i<nv.length; i++) {
                if (nv[i] != null) {
                    Parameter param = new Parameter(Parameter.LOCATION_QUERY, nv[i].getName(), "String");
                    params.add(param);
                }
            }
        }
        NamedValue[] headers = request.getHeaders();
        for (int i=0; i<headers.length; i++) {
            if (headers[i].getName().equals("Cookie")) {
                String cookies = headers[i].getValue();
                NamedValue[] nv = NamedValue.splitNamedValues(cookies, "; *", "=");
                for (int j=0; j<nv.length; j++) {
                    if (nv[j] != null) {
                        Parameter param = new Parameter(Parameter.LOCATION_COOKIE, nv[j].getName(), "String");
                        params.add(param);
                    }
                }
            }
        }
        if (request.getMethod().equals("POST")) {
            String type = request.getHeader("Content-Type");
            if (type != null && type.equals("application/x-www-form-urlencoded")) {
                byte[] content = request.getContent();
                if (content != null && content.length>0) {
                    String text = new String(content);
                    NamedValue[] nv = NamedValue.splitNamedValues(text, "&", "=");
                    for (int i=0; i<nv.length; i++) {
                        if (nv[i] != null) {
                            Parameter param = new Parameter(Parameter.LOCATION_BODY, nv[i].getName(), "String");
                            params.add(param);
                        }
                    }
                }
            }
        }
        return params;
    }
    
}
