/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * Cookie.java
 *
 * Created on September 10, 2003, 11:01 PM
 */

package org.owasp.webscarab.model;

import java.util.Date;
import java.util.logging.Logger;

/**
 * Represents a cookie received from a web server
 *
 * From rfc 2109
 *
 *   The syntax for the Set-Cookie response header is
 *
 *   set-cookie      =       "Set-Cookie:" cookies
 *   cookies         =       1#cookie
 *   cookie          =       NAME "=" VALUE *(";" cookie-av)
 *   NAME            =       attr
 *   VALUE           =       value
 *   cookie-av       =       "Comment" "=" value
 *                   |       "Domain" "=" value
 *                   |       "Max-Age" "=" value
 *                   |       "Path" "=" value
 *                   |       "Secure"
 *                   |       "Version" "=" 1*DIGIT
 *
 *
 * added support for Microsoft's new httponly flag - untested, and largely unused!
 *
 * @author rdawes
 */

public class Cookie {
    
    private Date _date = null;
    private String _name = null;
    private String _value = null;
    private String _key = null;
    private String _comment = null;
    private String _domain = null;
    private String _path = null;
    private String _maxage = null;
    private boolean _secure = false;
    private String _version = null;
    private boolean _httponly = false;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /**
     * Creates a new instance of Cookie
     * @param date the date the cookie was created/received
     * @param url the URL the the cookie was sent back from
     * @param setHeader the actual "Set-Cookie" header value
     */
    public Cookie(Date date, HttpUrl url, String setHeader) {
        _date = date;
        _domain = url.getHost();
        _path = url.getPath();
        int index = _path.lastIndexOf("/");
        if (index > 0) {
            _path = _path.substring(0,index);
        } else {
            _path = "/";
        }
        parseHeader(setHeader);
        _key = _domain + _path + " " + _name;
    }
    
    
    /**
     * This variant of the constuctor should only be called when we are sure that the
     * Set-Cookie header already contains the domain and path.
     * e.g. when we are reading the cookies from disk
     * @param date The date the cookie was created or received
     * @param setHeader a complete Set-Cookie header
     */    
    public Cookie(Date date, String setHeader) {
        _date = date;
        parseHeader(setHeader);
        _key = _domain + _path + " " + _name;
    }
    
    private void parseHeader(String setHeader) {
        if (setHeader == null) {
            throw new NullPointerException("You may not pass a null value for setHeader");
        }
        String[] parts = setHeader.split(" *; *");
        if (parts.length < 1) {
            throw new IllegalArgumentException("The setHeader must have at least one part to it!");
        }
        String[] av = parts[0].split("=",2);
        if (av.length != 2) {
            throw new IllegalArgumentException("The header passed in must at least contain the name and value '" +parts[0] + "'");
        }
        _name = av[0];
        _value = av[1];
        for (int i=1; i<parts.length; i++) {
            if (parts[i].equalsIgnoreCase("secure")) {
                _secure = true;
            } else if (parts[i].equalsIgnoreCase("httponly")) {
                    _httponly = true;
            } else {
                av = parts[i].split("=", 2);
                if (av.length != 2) {
                    _logger.warning("Unknown cookie attribute '" + parts[i] + "'");
                } else if (av[0].equalsIgnoreCase("Comment")) {
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
    
    /**
     * an identifier for the cookie "name", made up of the domain, the path, and the name of the cookie
     * @return the identifier
     */    
    public String getKey() {
        return _key;
    }
    
    /**
     * returns the date/time the cookie was created
     * @return the Date
     */    
    public Date getDate() {
        return _date;
    }
    
    /**
     * returns the name of the cookie
     * @return the name of the cookie
     */    
    public String getName() {
        return _name;
    }
    
    /**
     * returns the value of the cookie
     * @return the value of the cookie
     */    
    public String getValue() {
        return _value;
    }

    /**
     * returns the domain of the cookie
     * @return the domain of the cookie
     */    
    public String getDomain() {
        return _domain;
    }
    
    /**
     * returns the maximum age of the cookie
     * @return the maximum age of the cookie
     */    
    public String getMaxAge() {
        return _maxage;
    }
    
    /**
     * returns the path of the cookie
     * @return the path of the cookie
     */    
    public String getPath() {
        return _path;
    }
    
    /**
     * indicates whether this cookie had the "secure" flag set
     * @return true if the "secure" flag was set
     */    
    public boolean getSecure() {
        return _secure;
    }
    
    /**
     * indicates whther this cookie had MS's "httpOnly" flag set
     * @return true if the "httpOnly" flag was set
     */    
    public boolean getHTTPOnly() {
        return _httponly;
    }
    
    /**
     * returns the version of the cookie
     * @return the version of the cookie
     */    
    public String getVersion() {
        return _version;
    }
    
    /**
     * returns the comment of the cookie
     * @return the comment of the cookie
     */    
    public String getComment() {
        return _comment;
    }
    
    /**
     * returns a string equivalent to the complete "Set-Cookie" header that would have been sent.
     * @return a string equivalent to the complete "Set-Cookie" header that would have been sent.
     */    
    public String setCookie() {
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
        if (_httponly) {
            buf.append("; httponly");
        }
        if (_version != null) {
            buf.append("; Version=" + _version);
        }
        return buf.toString();
    }
    
    /**
     *
     */    
    public String toString() {
        StringBuffer buff = new StringBuffer();
        buff.append(_date.getTime()).append(" ");
        buff.append(setCookie());
        return buff.toString();
    }

}
