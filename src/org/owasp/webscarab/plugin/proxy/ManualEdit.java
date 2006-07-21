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
 * ManualEdit.java
 *
 * Created on July 10, 2003, 4:46 PM
 */

package org.owasp.webscarab.plugin.proxy;

import java.io.IOException;
import java.util.logging.Logger;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author  rdawes
 */
public class ManualEdit extends ProxyPlugin {
    
    private static String INCLUDE = ".*";
    private static String EXCLUDE = ".*\\.(gif|jpg|png|css|js|ico|swf|axd.*)$";
    private static String CONTENT = "text/.*";
    
    private String _includeRegex = "";
    private String _excludeRegex = "";
    private String[] _interceptMethods = null;
    private boolean _interceptRequest = false;
    private boolean _interceptResponse = false;
    private String _interceptResponseRegex = "";
    private boolean _caseSensitive = false;
    
    private ManualEditUI _ui = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ManualEdit */
    public ManualEdit() {
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "ManualEdit.includeRegex";
        String value = Preferences.getPreference(prop, INCLUDE);
        _includeRegex = value;
        
        prop = "ManualEdit.excludeRegex";
        value = Preferences.getPreference(prop, EXCLUDE);
        _excludeRegex= value;
        
        prop = "ManualEdit.interceptMethods";
        value = Preferences.getPreference(prop, "GET, POST");
        _interceptMethods = value.split(" *, *");
        
        prop = "ManualEdit.interceptRequest";
        value = Preferences.getPreference(prop, "false");
        _interceptRequest = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
        
        prop = "ManualEdit.interceptResponse";
        value = Preferences.getPreference(prop, "false");
        _interceptResponse = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
        
        prop = "ManualEdit.interceptResponseRegex";
        value = Preferences.getPreference(prop, CONTENT);
        _interceptResponseRegex = value;
        
        prop = "ManualEdit.caseSensitive";
        value = Preferences.getPreference(prop, "false");
        _caseSensitive = value.equalsIgnoreCase("true") || value.equalsIgnoreCase("yes");
        
    }
    
    public String getPluginName() {
        return new String("Manual Edit");
    }
    
    public void setUI(ManualEditUI ui) {
        _ui = ui;
    }
    
    public void setIncludeRegex(String regex) {
        _includeRegex = regex;
        String prop = "ManualEdit.includeRegex";
        Preferences.setPreference(prop,regex);
    }
    
    public String getIncludeRegex() {
        return _includeRegex;
    }
    
    public void setExcludeRegex(String regex) {
        _excludeRegex = regex;
        String prop = "ManualEdit.excludeRegex";
        Preferences.setPreference(prop,regex);
    }
    
    public String getExcludeRegex() {
        return _excludeRegex;
    }
    
    public void setInterceptMethods(String[] methods) {
        _interceptMethods = methods;
        String value = "";
        if (methods.length>0) {
            value = methods[0];
            for (int i=1; i< methods.length; i++) {
                value = value + ", " + methods[i];
            }
        }
        String prop = "ManualEdit.interceptMethods";
        Preferences.setPreference(prop,value);
    }
    
    public String[] getInterceptMethods() {
        return _interceptMethods;
    }
    
    public void setInterceptRequest(boolean bool) {
        _interceptRequest = bool;
        String prop = "ManualEdit.interceptRequest";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptRequest() {
        return _interceptRequest;
    }
    
    public void setInterceptResponse(boolean bool) {
        _interceptResponse = bool;
        String prop = "ManualEdit.interceptResponse";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean getInterceptResponse() {
        return _interceptResponse;
    }
    
    public void setInterceptResponseRegex(String regex) {
        _interceptResponseRegex = regex;
        Preferences.setPreference("ManualEdit.interceptResponseRegex", regex);
    }
    
    public String getInterceptResponseRegex() {
        return _interceptResponseRegex;
    }
    
    public void setCaseSensitive(boolean bool) {
        _caseSensitive = bool;
        String prop = "ManualEdit.caseSensitive";
        Preferences.setPreference(prop,Boolean.toString(bool));
    }
    
    public boolean isCaseSensitive() {
        return _caseSensitive;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new Plugin(in);
    }
    
    private class Plugin implements HTTPClient {
        
        private HTTPClient _in;
        
        private Pattern _exclude;
        private Pattern _include;
        private Pattern _content;
        
        public Plugin(HTTPClient in) {
            _in = in;
            
            int flags = _caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
            try {
                _include = Pattern.compile(_includeRegex, flags);
                _exclude = Pattern.compile(_excludeRegex, flags);
                _content = Pattern.compile(_interceptResponseRegex, flags);
            } catch (PatternSyntaxException pse) {
                _logger.warning("Regex pattern is invalid, using ALL default patterns! " + pse.getMessage());
                try {
                    _include = Pattern.compile(INCLUDE);
                    _exclude = Pattern.compile(EXCLUDE);
                    _content = Pattern.compile(CONTENT);
                } catch (PatternSyntaxException pse2) {}
            }
        }
        
        public Response fetchResponse(Request request) throws IOException {
            if (_interceptRequest) {
                String url = request.getURL().toString();
                Matcher include = _include.matcher(url);
                Matcher exclude = _exclude.matcher(url);
                if (! exclude.matches() && include.matches()) {
                    String method = request.getMethod();
                    for (int i=0; i<_interceptMethods.length; i++) {
                        if (method.equals(_interceptMethods[i])) {
                            if (_ui != null) {
                                request = _ui.editRequest(request);
                                if (request == null)
                                    throw new IOException("Request aborted in Manual Edit");
                            }
                        }
                    }
                }
            }
            Response response = _in.fetchResponse(request);
            if (_interceptResponse) {
                String contentType = response.getHeader("Content-Type");
                if (contentType == null || ! _content.matcher(contentType).matches()) {
                    return response;
                }
                if (_ui != null) {
                    request = response.getRequest();
                    response = _ui.editResponse(request, response);
                    if (response == null) throw new IOException("Response aborted in Manual Edit");
                    if (response.getRequest() == null) response.setRequest(request);
                    response.addHeader("X-ManualEdit", "possibly modified");
                }
            }
            return response;
        }
        
    }
    
}
