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

// import org.owasp.util.StringUtil;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.proxy.ProxyPlugin;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class RevealHidden extends ProxyPlugin {
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public RevealHidden() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "RevealHidden.enabled";
        String value = Preferences.getPreference(prop, "false");
        _enabled = ("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Reveal Hidden");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "RevealHidden.enabled";
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
                String ct = response.getHeader("Content-Type");
                if (ct != null && ct.matches("text/.*")) {
                    byte[] content = response.getContent();
                    if (content != null) {
                        response.setContent(revealHidden(content));
                        response.addHeader("X-RevealHidden", "possibly modified");
                    }
                }
            }
            return response;
        }
        
        private byte[] revealHidden(byte[] content) {
            String text = new String(content);
            text = text.replaceAll("type=\"[Hh][Ii][Dd][Dd][Ee][Nn]\"", "  type=\"text\"");
            text = text.replaceAll("type='[Hh][Ii][Dd][Dd][Ee][Nn]'", "  type='text'");
            text = text.replaceAll("type=[Hh][Ii][Dd][Dd][Ee][Nn]", "  type=text");
            return text.getBytes();
        }

    }
    
}
