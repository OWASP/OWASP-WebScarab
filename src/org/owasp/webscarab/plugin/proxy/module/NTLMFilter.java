/*
 * RevealHidden.java
 *
 * Created on July 13, 2003, 7:39 PM
 */

package org.owasp.webscarab.plugin.proxy.module;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.proxy.AbstractProxyPlugin;

import java.util.Properties;
import java.util.StringTokenizer;

import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class NTLMFilter extends AbstractProxyPlugin {
    
    private boolean _enabled = false;
    
    /** Creates a new instance of RevealHidden */
    public NTLMFilter() {
        setDefaultProperty("NTLMFilter.enabled","true");
        parseProperties();
    }
    
    public void parseProperties() {
        String prop = "NTLMFilter.enabled";
        String value = _prop.getProperty(prop);
        setEnabled("true".equalsIgnoreCase( value ) || "yes".equalsIgnoreCase( value ));
    }
    
    public String getPluginName() {
        return new String("Filter NTLM auth");
    }
    
    public void setEnabled(boolean bool) {
        _enabled = bool;
        String prop = "NTLMFilter.enabled";
        setProperty(prop,Boolean.toString(bool));
    }

    public boolean getEnabled() {
        return _enabled;
    }
    
    public HTTPClient getProxyPlugin(HTTPClient in) {
        return new ProxyPlugin(in);
    }    
    
    private class ProxyPlugin implements HTTPClient {
    
        private HTTPClient _in;
        
        public ProxyPlugin(HTTPClient in) {
            _in = in;
        }
        
        public Response fetchResponse(Request request) throws IOException {
            Response response = _in.fetchResponse(request);
            if (_enabled) {
                boolean changed = false;
                String[][] headers = response.getHeaders();
                for (int i=0; i< headers.length; i++) {
                    if (headers[i][0].equals("WWW-Authenticate") || 
                        headers[i][0].equals("Proxy-Authenticate")) {
                        String value = headers[i][1];
                        String scheme = value.substring(0, value.indexOf(" "));
                        if (scheme.equalsIgnoreCase("Basic")) {
                            int realmstart = value.indexOf("realm=\"")+7;
                            int realmend = value.indexOf("\"",realmstart);
                            int nextscheme = value.indexOf(",", realmend);
                            String realm = value.substring(realmstart, realmend);
                            if (nextscheme > -1) {
                                headers[i][1] = value.substring(0, nextscheme -1);
                                changed = true;
                            }
                        } else {
                            headers[i][1] = null;
                            changed = true;
                        }
                    }
                }
                if (changed) {
                    response.setHeaders(new String[0][0]);
                    for (int i=0; i< headers.length; i++) {
                        if (headers[i][1] != null) {
                            response.addHeader(headers[i][0], headers[i][1]);
                        }
                    }
                    response.addHeader("X-NTLMFilter", "modified");
                }
            }
            return response;
        }
        
    }
    
}
