/***********************************************************************
 *
 * $CVSHeader$
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
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package org.owasp.webscarab.plugin.wsfed;

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
public class WSFederation implements Plugin {

    private Thread _runThread = null;
    private final WSFederationModel model;
    private Logger _logger = Logger.getLogger(getClass().getName());

    public WSFederation(Framework framework) {
        this.model = new WSFederationModel(framework.getModel());
    }

    public WSFederationModel getModel() {
        return this.model;
    }

    @Override
    public String getPluginName() {
        return "WS-Federation";
    }

    @Override
    public void setSession(String type, Object store, String session) throws StoreException {
        // empty
    }

    @Override
    public void run() {
        this.model.setStatus("Started");

        this.model.setRunning(true);
        _runThread = Thread.currentThread();

        this.model.setStopping(false);
        while (!this.model.isStopping()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
            }
        }
        this.model.setRunning(false);
        this.model.setStatus("Stopped");
    }

    @Override
    public boolean isRunning() {
        return this.model.isRunning();
    }

    @Override
    public boolean isBusy() {
        return this.model.isBusy();
    }

    @Override
    public String getStatus() {
        return this.model.getStatus();
    }

    @Override
    public boolean stop() {
        this.model.setStopping(true);
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !this.model.isRunning();
    }

    @Override
    public boolean isModified() {
        return this.model.isModified();
    }

    @Override
    public void flush() throws StoreException {
        // empty
    }

    @Override
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        boolean wsigninMessage = false;
        String wtrealm = null;
        String wresult = null;
        NamedValue[] values = null;
        
        String method = request.getMethod();
        if (method.equals("GET")) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                values = NamedValue.splitNamedValues(query, "&", "=");
            }
        } else if (method.equals("POST")) {
            byte[] requestContent = request.getContent();
            if (requestContent != null && requestContent.length > 0) {
                String body = new String(requestContent);
                values = NamedValue.splitNamedValues(
                        body, "&", "=");
            }
        }

        if (null != values) {
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if ("wa".equals(name)) {
                    if ("wsignin1.0".equals(value)) {
                        wsigninMessage = true;
                    }
                } else if ("wtrealm".equals(name)) {
                    wtrealm = value;
                } else if ("wresult".equals(name)) {
                    wresult = value;
                }
            }
        }

        if (wsigninMessage) {
            if (null != wtrealm) {
                this.model.setSignInRequestMessage(id, wtrealm);
            } else if (null != wresult) {
                this.model.setSignInResponseMessage(id, wresult);
            }
        }
    }

    @Override
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }

    @Override
    public Object getScriptableObject() {
        return null;
    }
}
