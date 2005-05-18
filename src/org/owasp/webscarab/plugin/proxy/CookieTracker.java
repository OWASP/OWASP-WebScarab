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
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.util.Date;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.Framework;

/**
 *
 * @author  rdawes
 */
public class CookieTracker extends ProxyPlugin {
    
    private FrameworkModel _model = null;
    
    private boolean _injectRequests = false;
    private boolean _readResponses = false;
    
    /** Creates a new instance of CookieTracker */
    public CookieTracker(Framework framework) {
        _model = framework.getModel();
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "CookieTracker.injectRequests";
        String value = Preferences.getPreference(prop, "false");
        _injectRequests = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
        prop = "CookieTracker.readResponses";
        value = Preferences.getPreference(prop, "true");
        _readResponses = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Cookie Tracker");
    }
    
    public void setInjectRequests(boolean bool) {
        _injectRequests = bool;
        String prop = "CookieTracker.injectRequests";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }

    public boolean getInjectRequests() {
        return _injectRequests;
    }
    
    public void setReadResponses(boolean bool) {
        _readResponses = bool;
        String prop = "CookieTracker.readResponses";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }

    public boolean getReadResponses() {
        return _readResponses;
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
            if (_injectRequests) {
                // FIXME we should do something about any existing cookies that are in the Request
                // they could have been set via JavaScript, or some such!
                Cookie[] cookies = _model.getCookiesForUrl(request.getURL());
                if (cookies.length>0) {
                    StringBuffer buff = new StringBuffer();
                    buff.append(cookies[0].getName()).append("=").append(cookies[0].getValue());
                    for (int i=1; i<cookies.length; i++) {
                        buff.append("; ").append(cookies[i].getName()).append("=").append(cookies[i].getValue());
                    }
                    request.setHeader("Cookie", buff.toString());
                }
            }
            Response response = _in.fetchResponse(request);
            if (_readResponses && response != null) {
                NamedValue[] headers = response.getHeaders();
                for (int i=0; i<headers.length; i++) {
                    if (headers[i].getName().equalsIgnoreCase("Set-Cookie") || headers[i].getName().equalsIgnoreCase("Set-Cookie2")) {
                        Cookie cookie = new Cookie(new Date(), request.getURL(), headers[i].getValue());
                        _model.addCookie(cookie);
                    }
                }
            }
            return response;
        }
        
    }
    
}
