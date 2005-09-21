/*
 * Parameter.java
 *
 * Created on 23 February 2005, 08:24
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.HttpUrl;

import java.util.Date;
import java.util.List;
import java.util.ArrayList;

/**
 *
 * @author  rogan
 */
public class Parameter {
    
    public static final Parameter[] NO_PARAMS = new Parameter[0];
    
    public static final String LOCATION_PATH = "Path";
    public static final String LOCATION_FRAGMENT = "Fragment";
    public static final String LOCATION_QUERY = "Query";
    public static final String LOCATION_COOKIE = "Cookie";
    public static final String LOCATION_BODY = "Body";
    
    private String _location;
    private String _name;
    private String _type;
    private Object _value;
    
    public static String[] getParameterLocations() {
        return new String[] {
            LOCATION_PATH,
                    LOCATION_FRAGMENT,
                    LOCATION_QUERY,
                    LOCATION_COOKIE,
                    LOCATION_BODY,
        };
    }
    
    /** Creates a new instance of Parameter */
    public Parameter(String location, String name, String type, Object value) {
        _location = location;
        _name = name;
        _type = type;
        if (value == null)
            throw new NullPointerException("Value may not be null");
        _value = value;
    }
    
    public String getLocation() {
        return _location;
    }
    
    public String getName() {
        return _name;
    }
    
    public String getType() {
        return _type;
    }
    
    public Object getValue() {
        return _value;
    }
    
    public String toString() {
        return _location + ":" + _name + "(" + _type +") = " + _value;
    }
    
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Parameter)) return false;
        Parameter that = (Parameter) obj;
        return (_location.equals(that._location) && _name.equals(that._name) && _type.equals(that._type) && _value.equals(that._value));
    }
    
    public static Parameter[] getParameters(Request request) {
        List parameters = new ArrayList();
        String method = request.getMethod();
        HttpUrl url = request.getURL();
        
        String query = url.getQuery();
        String fragments = url.getFragment();
        if (url.getParameters() != null) url = url.getParentUrl();
        String contentType = request.getHeader("Content-Type");
        
        if (fragments != null) {
            NamedValue[] values = NamedValue.splitNamedValues(fragments, "&", "=");
            for (int i=0; i<values.length; i++) {
                parameters.add(new Parameter(Parameter.LOCATION_FRAGMENT, values[i].getName(), "STRING", values[i].getValue()));
            }
        }
        if (query != null) {
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            for (int i=0; i<values.length; i++) {
                parameters.add(new Parameter(Parameter.LOCATION_QUERY, values[i].getName(), "STRING", values[i].getValue()));
            }
        }
        NamedValue[] headers = request.getHeaders();
        for (int i=0; i<headers.length; i++) {
            if (headers[i].getName().equals("Cookie")) {
                NamedValue[] cookies = NamedValue.splitNamedValues(headers[i].getValue(), "; *", "=");
                for (int j=0; j<cookies.length; j++) {
                    parameters.add(new Parameter(Parameter.LOCATION_COOKIE, cookies[j].getName(), "STRING",  cookies[j].getValue()));
                }
            }
        }
        if (method.equals("POST")) {
            if (contentType != null) {
                Parameter[] body = getParamsFromContent(contentType, request.getContent());
                for (int i=0; i< body.length; i++) {
                    parameters.add(body[i]);
                }
            }
        }
        return (Parameter[]) parameters.toArray(NO_PARAMS);
    }
    
    public static Parameter[] getParamsFromContent(String contentType, byte[] content) {
        if (contentType.equals("application/x-www-form-urlencoded")) {
            String body = new String(content);
            NamedValue[] nv = NamedValue.splitNamedValues(body, "&", "=");
            Parameter[] params = new Parameter[nv.length];
            for (int i=0; i< nv.length; i++) {
                params[i] = new Parameter(Parameter.LOCATION_BODY, nv[i].getName(), "STRING", nv[i].getValue());
            }
            return params;
        }
        // FIXME do Multi-part here, too
        return new Parameter[0];
    }
    
    
}
