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
 * $Id: Fuzzer.java,v 1.7 2005/09/07 15:41:11 rogan Exp $
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.NamedValue;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Hook;

import org.owasp.webscarab.util.Encoding;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import java.util.logging.Logger;

import java.net.URL;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.net.MalformedURLException;

public class Fuzzer implements Plugin {
    
    private static Parameter[] NO_PARAMS = new Parameter[0];
    
    private FuzzerModel _model = null;
    private Framework _framework = null;
    private FuzzFactory _fuzzFactory = new FuzzFactory();
    
    private AsyncFetcher _fetcher = null;
    private int _threads = 4;
    
    private Thread _runThread = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private int _fuzzPriority = -1;
    
    public Fuzzer(Framework framework) {
        _framework = framework;
        _model = new FuzzerModel(_framework.getModel());
        loadFuzzStrings();
    }
    
    private void loadFuzzStrings() {
        int i = 0;
        String description;
        while ((description = Preferences.getPreference("Fuzz." + i + ".description")) != null) {
            String location = Preferences.getPreference("Fuzz." + i + ".location");
            if (location != null && !description.equals("")) {
                try {
                    URL url = new URL(location);
                    _fuzzFactory.loadFuzzStrings(description, url.openStream());
                } catch (IOException ioe) {
                    _logger.warning("Error loading \"" + description + "\" from " + location + " : " + ioe.getMessage());
                }
            }
            i++;
        }
    }
    
    public FuzzFactory getFuzzFactory() {
        return _fuzzFactory;
    }
    
    public FuzzerModel getModel() {
        return _model;
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Fuzzer");
    }
    
    public void run() {
        _model.setStatus("Started");
        _model.setStopping(false);
        _runThread = Thread.currentThread();
        
        // start the fetchers
        _fetcher = new AsyncFetcher("Fuzzer", _threads);
        
        _model.setRunning(true);
        while (!_model.isStopping()) {
            // queue them as fast as they come, sleep a bit otherwise
            boolean submittedRequest = queueRequests();
            boolean gotResponse = dequeueResponses();
            if (!submittedRequest && !gotResponse) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
            }
        }
        _fetcher.stop();
        _model.setRunning(false);
        _runThread = null;
        _model.setStatus("Stopped");
    }
    
    public void startFuzzing() {
        int count = _model.getFuzzParameterCount();
        if (count>0 && _model.getFuzzUrl() != null) {
            _model.setBusyFuzzing(true);
        } else {
            _logger.warning("Can't fuzz if there are no parameters or URL");
        }
    }
    
    private Request constructCurrentFuzzRequest() throws MalformedURLException {
        Request request = new Request();
        request.setMethod(_model.getFuzzMethod());
        request.setVersion(_model.getFuzzVersion());
        int count = _model.getFuzzHeaderCount();
        // _logger.info("Got headers: " + count);
        for (int i=0; i<count; i++) {
            // _logger.info("Header is " + _model.getFuzzHeader(i));
            request.addHeader(_model.getFuzzHeader(i));
        }
        if (request.getMethod().equals("POST")) {
            request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        }
        String url = _model.getFuzzUrl().toString();
        String path = null;
        String fragment = null;
        String query = null;
        String cookie = null;
        ByteArrayOutputStream content = null;
        count = _model.getFuzzParameterCount();
        for (int i=0; i<count; i++) {
            Parameter parameter = _model.getFuzzParameter(i);
            Object value = _model.getFuzzParameterValue(i);
            String location = parameter.getLocation();
            if (location.equals(Parameter.LOCATION_PATH)) {
                if (path == null) {
                    path = (String) value;
                } else {
                    path = path + "/" + (value == null ? "" : (String) value);
                }
            } else if (location.equals(Parameter.LOCATION_FRAGMENT)) {
                String frag = parameter.getName();
                if (frag == null) {
                    frag = (String) value;
                } else if (value == null) {
                    frag = frag + "=" + Encoding.urlEncode((String) value);
                } else {
                    frag = null;
                }
                if (fragment == null) {
                    fragment = frag;
                } else if (frag != null) {
                    fragment = fragment + "&" + frag;
                }
            } else if (location.equals(Parameter.LOCATION_QUERY)) {
                String q = parameter.getName() + "=" + Encoding.urlEncode((String) value);
                if (query == null) {
                    query = q;
                } else {
                    query = query + "&" + q;
                }
            } else if (location.equals(Parameter.LOCATION_COOKIE)) {
                String c = parameter.getName() + "=" + (String) value;
                if (cookie == null) {
                    cookie = c;
                } else {
                    cookie = cookie + "; " + cookie;
                }
            } else if (location.equals(Parameter.LOCATION_BODY)) {
                // FIXME - Assumes this is normal form data
                String b = parameter.getName() + "=" + Encoding.urlEncode((String) value);
                if (content == null) {
                    content = new ByteArrayOutputStream();
                    try { content.write(b.getBytes()); }
                    catch (IOException ioe) {}
                } else {
                    try { content.write(("&"+b).getBytes()); }
                    catch (IOException ioe) {}
                }
            } else {
                _logger.severe("Skipping unknown parameter location " + location);
            }
        }
        if (path != null) url = url + "/" + path;
        if (fragment != null) url = url + ";" + fragment;
        if (query != null) url = url + "?" + query;
        request.setURL(new HttpUrl(url));
        if (cookie != null) request.addHeader("Cookie", cookie);
        if (content != null) {
            request.setHeader("Content-Length", Integer.toString(content.size()));
            request.setContent(content.toByteArray());
        } else if (request.getMethod().equals("POST")) {
            request.setHeader("Content-Length", "0");
        }
        return request;
    }
    
    public void pauseFuzzing() {
        _model.setBusyFuzzing(false);
    }
    
    public void stopFuzzing() {
        _model.setBusyFuzzing(false);
    }
    
    private boolean queueRequests() {
        if (! _fetcher.hasCapacity()) return false;
        if (!_model.isBusyFuzzing()) return false;
        try {
            Request request = constructCurrentFuzzRequest();
            _fetcher.submit(request);
            if (!_model.incrementFuzzer()) {
                _model.setBusyFuzzing(false);
            }
        } catch (Exception e) {
            _model.setBusyFuzzing(false);
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    private boolean dequeueResponses() {
        // see if there are any responses waiting for us
        if (! _fetcher.hasResponse()) {
            return false;
        }
        Response response = null;
        try {
            response = _fetcher.receive();
            if (response == null) {
                _logger.warning("No response!");
                return false;
            }
            if (response.getStatus().equals("400")) {
                _logger.warning("Bad request");
                _model.setBusyFuzzing(false);
            }
        } catch (IOException ioe) {
            _logger.warning("Caught exception : " + ioe.getMessage());
            _model.setBusyFuzzing(false);
            return false;
        }
        Request request = response.getRequest();
        if (request == null) {
            _logger.warning("Got a null request from the response!");
            return false;
        }
        _framework.addConversation(request, response, "Fuzzer");
        return true;
    }
    
    public boolean stop() {
        _model.setStatus("Stopped");
        _model.setRunning(false);
        return ! _model.isRunning();
    }
    
    public void setSession(String type, Object store, String session) throws org.owasp.webscarab.model.StoreException {
    }
    
    public void flush() throws StoreException {
    }
    
    public boolean isBusy() {
        return _model.isBusy();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        Signature signature = new Signature(request);
        _model.addSignature(signature);
        if (!response.getStatus().equals("304")) {
            byte[] content = response.getContent();
            if (content == null) content = new byte[0];
            String checksum = Encoding.hashMD5(content);
            _model.addChecksum(signature.getUrl(), checksum);
        }
    }
    
    private Parameter[] getParameters(Request request) {
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
                parameters.add(new Parameter("FRAGMENT", values[i].getName(), "STRING"));
            }
        }
        if (query != null) {
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            for (int i=0; i<values.length; i++) {
                parameters.add(new Parameter("URL", values[i].getName(), "STRING"));
            }
        }
        NamedValue[] headers = request.getHeaders();
        for (int i=0; i<headers.length; i++) {
            if (headers[i].getName().equals("Cookie")) {
                NamedValue[] cookies = NamedValue.splitNamedValues(headers[i].getValue(), "; *", "=");
                for (int j=0; j<cookies.length; j++) {
                    parameters.add(new Parameter("COOKIE", cookies[j].getName(), "STRING"));
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
    
    private Parameter[] getParamsFromContent(String contentType, byte[] content) {
        if (contentType.equals("application/x-www-form-urlencoded")) {
            String body = new String(content);
            NamedValue[] nv = NamedValue.splitNamedValues(body, "&", "=");
            Parameter[] params = new Parameter[nv.length];
            for (int i=0; i< nv.length; i++) {
                params[i] = new Parameter("BODY", nv[i].getName(), "STRING");
            }
            return params;
        }
        // FIXME do Multi-part here, too
        return new Parameter[0];
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
}
