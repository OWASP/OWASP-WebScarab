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
 * $Id: Fuzzer.java,v 1.2 2005/03/24 07:12:03 rogan Exp $
 */

package org.owasp.webscarab.plugin.fuzz;

import org.owasp.webscarab.httpclient.AsyncFetcher;

import org.owasp.webscarab.model.SiteModel;
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

import java.util.logging.Logger;

import java.io.IOException;

public class Fuzzer implements Plugin {
    
    private FuzzerModel _model = null;
    private Framework _framework = null;
    
    private AsyncFetcher _fetcher = null;
    private int _threads = 4;
    
    private boolean _running = false;
    private boolean _stopping = false;
    private String _status = "Stopped";
    
    private Thread _runThread = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    public Fuzzer(Framework framework) {
        _framework = framework;
        _model = new FuzzerModel(_framework.getModel());
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
        _status = "Started";
        _stopping = false;
        _runThread = Thread.currentThread();
        
        // start the fetchers
        _fetcher = new AsyncFetcher("Fuzzer", _threads);
        
        _running = true;
        // if (_ui != null) _ui.setEnabled(_running);
        while (!_stopping) {
            // queue them as fast as they come, sleep a bit otherwise
            if (!queueRequests() && !dequeueResponses()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
            } else {
                Thread.yield();
            }
        }
        _fetcher.stop();
        _running = false;
        _runThread = null;
        // if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
    }
    
    public void queueUrls(HttpUrl[] urls) {
        for (int i=0; i<urls.length; i++) {
            _model.queueUrl(urls[i]);
        }
    }
    
    public void clearUrlQueue() {
        _logger.info("Clearing url queue");
        _model.clearUrlQueue();
    }
    
    private boolean queueRequests() {
        if (_model.getQueuedUrlCount() == 0) return false;
        if (! _fetcher.hasCapacity()) return false;
        while (_model.getQueuedUrlCount() > 0 && _fetcher.hasCapacity()) {
            HttpUrl url = _model.getQueuedUrl();
            if (_model.isAppCandidate(url)) {
                Request request = new Request();
                request.setMethod("GET");
                request.setURL(url);
                request.setVersion("HTTP/1.0");
                request.setHeader("Host", url.getHost());
                if (_model.isAuthenticationRequired(url)) {
                    String auth = "Basic d2ViZ29hdDp3ZWJnb2F0";
                    request.addHeader("Authorization", auth);
                }
                _fetcher.submit(request);
                _logger.info("Submitted " + url);
            }
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
            if (response == null)
                return false;
        } catch (IOException ioe) {
            return false;
        }
        Request request = response.getRequest();
        if (request == null) {
            _logger.warning("Got a null request from the response!");
            return false;
        }
        if (response.getStatus().startsWith("401")) {
            _model.setAuthenticationRequired(request.getURL(), true);
        } else {
            _framework.addConversation(request, response, "Fuzzer");
        }
        return true;
    }
    
    public boolean stop() {
        // if (_ui != null) _ui.stopped();
        _status = "Stopped";
        _running = false;
        return ! _running;
    }
    
    public void setSession(String type, Object store, String session) throws org.owasp.webscarab.model.StoreException {
    }
    
    public void flush() throws StoreException {
    }
    
    public boolean isBusy() {
        return false;
    }
    
    public boolean isRunning() {
        return _running;
    }
    
    public String getStatus() {
        return _status;
    }
    
    public boolean isModified() {
        return true;
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        String method = request.getMethod();
        HttpUrl url = request.getURL();
        String status = response.getStatus();
        if (status.startsWith("401")) {
            _model.setAuthenticationRequired(url, true);
            return;
        }
        String query = url.getQuery();
        String fragments = url.getFragment();
        if (url.getParameters() != null) url = url.getParentUrl();
        String contentType = request.getHeader("Content-Type");
        
        Signature signature = new Signature(method, url, contentType);
        
        if (fragments != null) {
            NamedValue[] values = NamedValue.splitNamedValues(fragments, "&", "=");
            for (int i=0; i<values.length; i++) {
                signature.addParameter(new Parameter("FRAGMENT", values[i].getName(), "STRING"));
            }
        }
        if (query != null) {
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            for (int i=0; i<values.length; i++) {
                signature.addParameter(new Parameter("URL", values[i].getName(), "STRING"));
            }
        }
        NamedValue[] headers = request.getHeaders();
        for (int i=0; i<headers.length; i++) {
            if (headers[i].getName().equals("Cookie")) {
                NamedValue[] cookies = NamedValue.splitNamedValues(headers[i].getValue(), "; *", "=");
                for (int j=0; j<cookies.length; j++) {
                    signature.addParameter(new Parameter("COOKIE", cookies[j].getName(), "STRING"));
                }
            }
        }
        if (method.equals("POST")) {
            if (contentType != null) {
                Parameter[] body = getParamsFromContent(contentType, request.getContent());
                for (int i=0; i< body.length; i++) {
                    signature.addParameter(body[i]);
                }
            }
        }
        if (signature.getParameters().length > 0 || method.equals("POST")) {
            _model.addSignature(url, signature, id);
        } else {
            _model.setBlankRequest(url);
        }
        byte[] content = response.getContent();
        if (content != null && content.length>0) {
            String checksum = Encoding.hashMD5(content);
            _model.addCheckSum(url,  checksum);
        }
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
