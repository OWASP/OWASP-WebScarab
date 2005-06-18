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
 * SessionidAnalysis.java
 *
 * Created on 16 November 2003, 05:19
 */

package org.owasp.webscarab.plugin.sessionid;

import org.owasp.webscarab.httpclient.AsyncFetcher;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.Hook;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.math.BigInteger;

import java.util.Date;
import java.util.Map;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.Timer;
import java.util.TimerTask;

import java.util.logging.Logger;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.swing.event.EventListenerList;

/**
 *
 * @author  rdawes
 */
public class SessionIDAnalysis implements Plugin {
    
    private Framework _framework = null;
    private SessionIDModel _model;
    
    private AsyncFetcher _fetcher;
    private int _threads = 4;
    
    private String _name = null;
    private String _regex = null;
    private int _count = 0;
    
    private Request _request = null;
    private Response _response = null;
    
    private Thread _runThread = null;
    
    private HTTPClient _hc = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private EventListenerList _listenerList = new EventListenerList();
    
    /** Creates a new instance of SessionidAnalysis */
    public SessionIDAnalysis(Framework framework) {
        _framework = framework;
        _model = new SessionIDModel(framework.getModel());
    }
    
    public SessionIDModel getModel() {
        return _model;
    }
    
    public void setSession(String type, Object store, String session) throws StoreException {
        if (type.equals("FileSystem") && (store instanceof File)) {
            _model.setStore(new FileSystemStore((File) store));
        } else {
            throw new StoreException("Store type '" + type + "' is not supported in " + getClass().getName());
        }
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Session ID Analysis");
    }
    
    public void run() {
        _model.setStatus("Started");
        _hc = HTTPClientFactory.getInstance().getHTTPClient();
        
        _fetcher = new AsyncFetcher("SessionID", _threads);
        
        Timer requestTimer = new Timer(true);
        requestTimer.schedule(new TimerTask() {
            public void run() {
                queueRequest();
            }
        }, 1000, 100); // wait 1 seconds to initialise, then every tenth of a second
        
        _model.setRunning(true);
        _runThread = Thread.currentThread();
        
        _model.setStopping(false);
        Response response;
        while (! _model.isStopping()) {
            try {
                while (_fetcher.hasResponse()) {
                    response = _fetcher.receive();
                    if (response != null) {
                        Map ids = getIDsFromResponse(response, _name, _regex);
                        Iterator it = ids.keySet().iterator();
                        while (it.hasNext()) {
                            String key = (String) it.next();
                            SessionID id = (SessionID) ids.get(key);
                            _model.addSessionID(key, id);
                        }
                    }
                }
            } catch (IOException ioe) {
                _logger.info("IOException " + ioe.getMessage());
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {}
        }
        requestTimer.cancel();
        _request = null;
        _response = null;
        _fetcher.stop();
        _hc = null;
        _model.setRunning(false);
        _model.setStatus("Stopped");
    }
    
    public Map getIDsFromResponse(Response response, String name, String regex) {
        Map ids = new TreeMap();
        Request request = response.getRequest();
        if (request == null) {
            System.out.println("Request was null?");
            return ids;
        }
        HttpUrl url = request.getURL();
        Date date = new Date();
        NamedValue[] headers = response.getHeaders();
        if (name != null && !name.equals("") && regex != null) {
            String location = response.getHeader("Location");
            if (location != null) {
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(location);
                if (matcher.matches() && matcher.groupCount() > 0) {
                    StringBuffer match = new StringBuffer();
                    for (int j=0; j<matcher.groupCount(); j++) {
                        match.append(matcher.group(j+1));
                    }
                    SessionID id = new SessionID(date, match.toString());
                    ids.put(name, id);
                }
            }
            String type = response.getHeader("Content-Type");
            if (type != null && type.startsWith("text/")) {
                String charset = "UTF-8";
                String body = null;
                try {
                    body = new String(response.getContent(), charset);
                } catch (UnsupportedEncodingException uee) {
                    body = new String(response.getContent());
                }
                
                Pattern pattern = Pattern.compile(regex, Pattern.MULTILINE | Pattern.DOTALL);
                Matcher matcher = pattern.matcher(body);
                if (matcher.matches() && matcher.groupCount() > 0) {
                    StringBuffer match = new StringBuffer();
                    for (int j=0; j<matcher.groupCount(); j++) {
                        match.append(matcher.group(j+1));
                    }
                    SessionID id = new SessionID(date, match.toString());
                    ids.put(name, id);
                }
            }
        } else {
            Pattern pattern = Pattern.compile("(.*)");
            if (regex != null && !regex.equals("")) pattern = Pattern.compile(regex);
            for (int i=0; i<headers.length; i++) {
                if (headers[i].getName().equalsIgnoreCase("Set-Cookie") || headers[i].getName().equalsIgnoreCase("Set-Cookie2")) {
                    Cookie cookie = new Cookie(date, url, headers[i].getValue());
                    Matcher matcher = pattern.matcher(cookie.getValue());
                    if (matcher.matches() && matcher.groupCount() > 0) {
                        StringBuffer match = new StringBuffer();
                        for (int j=0; j<matcher.groupCount(); j++) {
                            match.append(matcher.group(j+1));
                        }
                        SessionID id = new SessionID(date, match.toString());
                        ids.put(cookie.getKey(), id);
                    }
                }
            }
        }
        return ids;
    }
    
    public void fetch(Request request, String name, String regex, int count) {
        // throws a Runtime exception if this failes
        Pattern.compile(regex);
        
        _request = request;
        _name = name;
        _regex = regex;
        _count = count;
    }
    
    private void queueRequest() {
        if (_request != null && _count > 0) { // if we have a request to fetch, and there are some outstanding
            if (_fetcher.hasCapacity() && _fetcher.submit(_request)) {
                _count --;
                return;
            }
        }
    }
    
    public void setRequest(Request request) {
        _request = request;
    }
    
    public void fetchResponse() throws IOException {
        _response = _hc.fetchResponse(_request);
    }
    
    public Response getResponse() {
        return _response;
    }
    
    /** This function provides for setting a different calculator
     * i.e. one that calculates the sessionid based on different
     * criteria to the DefaultCalculator, such as character ordering, etc
     *
     * No interface component uses it as yet, though
     */
    public void setCalculator(String key, Calculator calc) {
        _model.setCalculator(key, calc);
    }
    
    public boolean stop() {
        _model.setStopping(true);
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !_model.isRunning();
    }
    
    public void flush() throws StoreException {
        _model.flush();
    }
    
    public boolean isBusy() {
        return _count > 0;
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        HttpUrl url = request.getURL();
        String cookie = request.getHeader("Cookie");
        if (cookie != null) _model.addRequestCookie(id, cookie);
        cookie = response.getHeader("Set-Cookie");
        if (cookie != null) {
            Cookie c = new Cookie(new Date(), cookie);
            _model.addResponseCookie(id, url, c);
        }
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
}
