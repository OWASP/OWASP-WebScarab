/*
 * Cookie.java
 *
 * Created on September 10, 2003, 11:01 PM
 */

package org.owasp.webscarab.model;

import java.net.URL;

/**
 *
 * @author  rdawes
 */
public class Cookie {
    /* From rfc 2109
     *
     *   The syntax for the Set-Cookie response header is
                                                                                
   set-cookie      =       "Set-Cookie:" cookies
   cookies         =       1#cookie
   cookie          =       NAME "=" VALUE *(";" cookie-av)
   NAME            =       attr
   VALUE           =       value
   cookie-av       =       "Comment" "=" value
                   |       "Domain" "=" value
                   |       "Max-Age" "=" value
                   |       "Path" "=" value
                   |       "Secure"
                   |       "Version" "=" 1*DIGIT

     *
     */
    
    private String _name;
    private String _value;
    private String _comment = null;
    private String _domain = null;
    private String _path = null;
    private String _maxage = null;
    private boolean _secure = false;
    private String _version = null;
    
    /** Creates a new instance of Cookie */
    public Cookie(URL url, String setHeader) {
        _domain = url.getHost();
        _path = url.getPath(); // FIXME : should we try to eliminate parameters in the path?
        int index = _path.lastIndexOf("/");
        if (index > 0) {
            _path = _path.substring(0,index-1);
        } else {
            _path = "/";
        }
        
        if (setHeader == null) {
            throw new NullPointerException("You may not pass a null value for setHeader");
        }
        String[] parts = setHeader.split(" *; *");
        if (parts.length < 1) {
            throw new IllegalArgumentException("The setHeader must have at least one part to it!");
        }
        String[] av = parts[0].split("=",2);
        if (av.length != 2) {
            throw new IllegalArgumentException("The header passed in must at least contain the name and value");
        }
        _name = av[0];
        _value = av[1];
        for (int i=1; i<parts.length; i++) {
            if (parts[i].equals("Secure")) {
                _secure = true;
            } else {
                av = parts[i].split("=", 2);
                if (av.length != 2) {
                    throw new IllegalArgumentException("Bad format for '" + parts[i] + "'");
                }
                if (av[0].equalsIgnoreCase("Comment")) {
                    _comment = av[1];
                } else if (av[0].equalsIgnoreCase("Domain")) {
                    _domain = av[1];
                } else if (av[0].equalsIgnoreCase("Path")) {
                    _path = av[1];
                } else if (av[0].equalsIgnoreCase("Max-Age")) {
                    _maxage = av[1];
                } else if (av[0].equalsIgnoreCase("Version")) {
                    _version = av[1];
                }
            }
        }
    }
    
    public String getName() {
        return _name;
    }
    
    public String getValue() {
        return _value;
    }
    
    public String getDomain() {
        return _domain;
    }
    
    public String getMaxAge() {
        return _maxage;
    }
    
    public String getPath() {
        return _path;
    }
    
    public boolean getSecure() {
        return _secure;
    }
    
    public String getVersion() {
        return _version;
    }
    
    public String toString() {
        StringBuffer buf = new StringBuffer();
        buf.append(_name + "=" + _value);
        if (_comment != null) {
            buf.append("; Comment=" + _comment);
        }
        if (_domain != null) {
            buf.append("; Domain=" + _domain);
        }
        if (_maxage != null) {
            buf.append("; Max-Age=" + _maxage);
        }
        if (_path != null) {
            buf.append("; Path=" + _path);
        }
        if (_secure) {
            buf.append("; Secure");
        }
        if (_version != null) {
            buf.append("; Version=" + _version);
        }
        return buf.toString();
    }
    
}
