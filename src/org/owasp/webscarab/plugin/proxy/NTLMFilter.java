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

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.proxy.ProxyPlugin;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class NTLMFilter extends ProxyPlugin {
    
    private boolean _enabled = false;
    
    private static NamedValue[] NO_HEADERS = new NamedValue[0];
    
    /** Creates a new instance of RevealHidden */
    public NTLMFilter() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "NTLMFilter.enabled";
        String value = Preferences.getPreference(prop, "true");
        _enabled = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Filter NTLM auth");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "NTLMFilter.enabled";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
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
            Response response = _in.fetchResponse(request);
            if (_enabled) {
                boolean changed = false;
                NamedValue[] headers = response.getHeaders();
                for (int i=0; i< headers.length; i++) {
                    if (headers[i].getName().equalsIgnoreCase("WWW-Authenticate") || 
                        headers[i].getName().equalsIgnoreCase("Proxy-Authenticate")) {
                        String value = headers[i].getValue();
                        String[] schemes = value.split(", *");
                        if (schemes.length > 1) {
                            for (int j=0; j<schemes.length; j++) {
                                if (schemes[j].startsWith("NTLM")) {
                                    schemes[j] = null;
                                    changed = true;
                                }
                            }
                            if (changed) {
                                value = "";
                                for (int j=0; j<schemes.length; j++) {
                                    if (schemes[j] != null) {
                                        if (value.length() > 0) value = value + ", ";
                                        value = value + schemes[j];
                                    }
                                }
                                headers[i] = new NamedValue(headers[i].getName(),value);
                            }
                        } else {
                            if (schemes[0].startsWith("NTLM")) {
                                headers[i] = null;
                                changed = true;
                            }
                        }
                    }
                }
                if (changed) {
                    response.setHeaders(NO_HEADERS);
                    for (int i=0; i< headers.length; i++) {
                        if (headers[i] != null) {
                            response.addHeader(headers[i]);
                        }
                    }
                    response.addHeader("X-NTLMFilter", "modified");
                }
            }
            return response;
        }
        
    }
    
}
