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
import java.util.regex.Pattern;
import java.util.regex.Matcher;

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
            /* We split this pattern into two parts, one before "hidden" and one after
             * Then it is simple to concatenate part 1 + "text" + part 2 to get an
             * "unhidden" input tag 
             */
            Pattern inputPattern = Pattern.compile("(<input.+?type\\s*=\\s*[\"']{0,1})hidden([\"']{0,1}.+?>)", Pattern.CASE_INSENSITIVE);
            Matcher inputMatcher = inputPattern.matcher(new String(content));
            StringBuffer outbuf = new StringBuffer();
            
            /* matched hidden input parameter */
            while(inputMatcher.find()) {
                String input = inputMatcher.group();
                String name = "noname";
                
                // extract hidden field name
                Pattern namePattern = Pattern.compile("name=[\"']{0,1}(\\w+)[\"']{0,1}", Pattern.CASE_INSENSITIVE);
                Matcher nameMatcher = namePattern.matcher(input);
                if (nameMatcher.find() && nameMatcher.groupCount() == 1){
                    name = nameMatcher.group(1);
                }
                
                // make hidden field a text field - there MUST be 2 groups
                // Note: this way we don't have to care about which quotes are being used
                input = inputMatcher.group(1) + "text" + inputMatcher.group(2);

                /* insert [hidden] <fieldname> before the field itself */
                inputMatcher.appendReplacement(outbuf, "<STRONG style=\"background-color: white;\"> [hidden field name =\"" + name + "\"]:</STRONG> "+ input + "<BR/>");
            }
            inputMatcher.appendTail(outbuf);
            return outbuf.toString().getBytes();
        }

    }

}
