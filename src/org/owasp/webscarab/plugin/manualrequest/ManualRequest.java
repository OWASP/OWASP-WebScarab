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
 * $Id: ManualRequest.java,v 1.11 2004/12/26 14:41:52 rogan Exp $
 */

package org.owasp.webscarab.plugin.manualrequest;

import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Plugin;

import java.io.IOException;

import java.util.Date;
import java.util.logging.Logger;

public class ManualRequest extends Plugin {
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private ManualRequestUI _ui = null;
    
    private HTTPClient _hc = null;
    
    private Request _request = null;
    private Response _response = null;
    private Date _responseDate = null;
    
    private SiteModel _model = null;
    private Framework _framework = null;
    
    private boolean _busy = false;
    private String _status = "Stopped";
    
    public ManualRequest(Framework framework) {
        _framework = framework;
    }
    
    /** The plugin name
     * @return The name of the plugin
     *
     */
    public String getPluginName() {
        return new String("Manual Request");
    }
    
    public void setSession(SiteModel model, String type, Object connection) {
        _model = model;
        if (_ui != null) _ui.setModel(model);
    }
    
    public void setUI(ManualRequestUI ui) {
        _ui = ui;
        if (_ui != null) _ui.setEnabled(_running);
    }
    
    public void setRequest(Request request) {
        _request = request;
        if (_ui != null) {
            _ui.responseChanged(null);
            _ui.requestChanged(request);
        }
    }
    
    public void fetchResponse() throws IOException {
        _busy = true;
        _status = "Started, Fetching response";
        if (_request != null) {
            _response = _hc.fetchResponse(_request);
            if (_response != null) {
                _responseDate = new Date();
                _framework.addConversation(_request, _response, "Manual Request");
                if (_ui != null) _ui.responseChanged(_response);
            }
        }
        _status = "Started, Idle";
        _busy = false;
    }
    
    public void addRequestCookies() {
        if (_request != null) {
            Cookie[] cookies = _model.getCookiesForUrl(_request.getURL());
            if (cookies.length>0) {
                StringBuffer buff = new StringBuffer();
                buff.append(cookies[0].getName()).append("=").append(cookies[0].getValue());
                for (int i=1; i<cookies.length; i++) {
                    buff.append("; ").append(cookies[i].getName()).append("=").append(cookies[i].getValue());
                }
                _request.setHeader(new NamedValue("Cookie", buff.toString()));
                if (_ui != null) _ui.requestChanged(_request);
            }
        }
    }
    
    public void updateCookies() {
        if (_response != null) {
            NamedValue[] headers = _response.getHeaders();
            for (int i=0; i<headers.length; i++) {
                if (headers[i].getName().equalsIgnoreCase("Set-Cookie") || headers[i].getName().equalsIgnoreCase("Set-Cookie2")) {
                    Cookie cookie = new Cookie(_responseDate, _request.getURL(), headers[i].getValue());
                    _model.addCookie(cookie);
                }
            }
        }
    }
    
    public void run() {
        _hc = HTTPClientFactory.getInstance().getHTTPClient();
        _running = true;
        // we do not run in our own thread, so we just return
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Started, Idle";
    }
    
    public boolean stop() {
        _hc = null;
        _running = false;
        // nothing to stop
        if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
        return ! _running;
    }
    
    public void flush() throws StoreException {
        // we do not manage our own store
    }
    
    public boolean isBusy() {
        return _busy;
    }
    
    public String getStatus() {
        return _status;
    }
    
    public boolean isModified() {
        return false;
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        // we do no analysis
    }
    
}
