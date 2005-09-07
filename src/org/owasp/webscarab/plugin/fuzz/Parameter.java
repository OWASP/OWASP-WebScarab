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
    
    public static final String LOCATION_PATH = "Path";
    public static final String LOCATION_FRAGMENT = "Fragment";
    public static final String LOCATION_QUERY = "Query";
    public static final String LOCATION_COOKIE = "Cookie";
    public static final String LOCATION_BODY = "Body";
    
    private String _location;
    private String _name;
    private String _type;
    
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
    public Parameter(String location, String name, String type) {
        _location = location;
        _name = name;
        _type = type;
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
    
    public String toString() {
        return _location + ":" + _name + "(" + _type +")";
    }
    
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Parameter)) return false;
        Parameter that = (Parameter) obj;
        return (_location.equals(that._location) && _name.equals(that._name) && _type.equals(that._type));
    }
    
}
