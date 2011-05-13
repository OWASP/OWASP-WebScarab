/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 FedICT
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
 */
package org.owasp.webscarab.plugin.openid;

import java.util.logging.Logger;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author Frank Cornelis
 */
public class OpenId implements Plugin {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final OpenIdModel openIdModel;
    private final OpenIdProxy openIdProxy;
    private Thread _runThread = null;

    public OpenId(Framework framework, OpenIdProxy openIdProxy) {
        this.openIdModel = new OpenIdModel(framework.getModel());
        this.openIdProxy = openIdProxy;
    }

    public String getPluginName() {
        return "OpenID";
    }

    public void setSession(String type, Object store, String session) throws StoreException {
        // empty
    }

    public void run() {
        this.openIdModel.setStatus("Started");

        this.openIdModel.setRunning(true);
        this._runThread = Thread.currentThread();

        this.openIdModel.setStopping(false);
        while (!this.openIdModel.isStopping()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
            }
        }
        this.openIdModel.setRunning(false);
        this.openIdModel.setStatus("Stopped");
    }

    public boolean isRunning() {
        return this.openIdModel.isRunning();
    }

    public boolean isBusy() {
        return this.openIdModel.isBusy();
    }

    public String getStatus() {
        return this.openIdModel.getStatus();
    }

    public boolean stop() {
        this.openIdModel.setStopping(true);
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !this.openIdModel.isRunning();
    }

    public boolean isModified() {
        return this.openIdModel.isModified();
    }

    public void flush() throws StoreException {
        // empty
    }

    public void analyse(ConversationID id, Request request, Response response, String origin) {
        String method = request.getMethod();
        if ("GET".equals(method)) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
                for (int i = 0; i < values.length; i++) {
                    String name = values[i].getName();
                    String value = Encoding.urlDecode(values[i].getValue());
                    if ("openid.ns".equals(name)) {
                        this.openIdModel.setOpenIDMessage(id, value);
                    } else if ("openid.mode".equals(name)) {
                        this.openIdModel.setOpenIDMessageType(id, value);
                    }
                }
            }
        }
    }

    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }

    public Object getScriptableObject() {
        return null;
    }

    public OpenIdModel getModel() {
        return this.openIdModel;
    }
    
    public OpenIdProxy getOpenIdProxy() {
        return this.openIdProxy;
    }
}
