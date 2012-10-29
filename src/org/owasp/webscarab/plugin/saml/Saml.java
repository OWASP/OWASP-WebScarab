/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2010 FedICT
 * Copyright (c) 2010 Frank Cornelis <info@frankcornelis.be>
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

package org.owasp.webscarab.plugin.saml;

import java.util.logging.Logger;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;

/**
 * WebScarab SAML plugin.
 * This plugin allows you to analyse SAML Messages.
 * 
 * @author Frank Cornelis
 */
public class Saml implements Plugin {

    private final SamlModel _model;
    private final SamlProxy samlProxy;
    private Logger _logger = Logger.getLogger(getClass().getName());
    private Thread _runThread = null;

    public Saml(Framework framework, SamlProxy samlProxy) {
        this._model = new SamlModel(framework.getModel());
        this.samlProxy = samlProxy;
        this.samlProxy.init(this._model);
    }

    public SamlProxy getSamlProxy() {
        return this.samlProxy;
    }

    @Override
    public void analyse(ConversationID id, Request request, Response response,
            String origin) {
        String method = request.getMethod();
        if (method.equals("POST")) {
            String contentType = request.getHeader("Content-Type");
            if (null != contentType) {
                if (contentType.equals("application/x-www-form-urlencoded")) {
                    byte[] requestContent = request.getContent();
                    if (requestContent != null && requestContent.length > 0) {
                        String body = new String(requestContent);
                        NamedValue[] namedValues = NamedValue.splitNamedValues(
                                body, "&", "=");
                        for (int idx = 0; idx < namedValues.length; idx++) {
                            NamedValue namedValue = namedValues[idx];
                            if ("SAMLResponse".equals(namedValue.getName())) {
                                this._model.setSAMLResponse(id, namedValue.getValue());
                            } else if ("SAMLRequest".equals(namedValue.getName())) {
                                this._model.setSAMLRequest(id, namedValue.getValue());
                            } else if ("RelayState".equals(namedValue.getName())) {
                                this._model.setRelayState(id, namedValue.getValue());
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public void flush() throws StoreException {
    }

    @Override
    public String getPluginName() {
        return "SAML";
    }

    @Override
    public Object getScriptableObject() {
        return null;
    }

    @Override
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }

    @Override
    public String getStatus() {
        return this._model.getStatus();
    }

    @Override
    public boolean isBusy() {
        return this._model.isBusy();
    }

    @Override
    public boolean isModified() {
        return this._model.isModified();
    }

    @Override
    public boolean isRunning() {
        return this._model.isRunning();
    }

    @Override
    public void run() {
        _model.setStatus("Started");

        _model.setRunning(true);
        _runThread = Thread.currentThread();

        _model.setStopping(false);
        while (!_model.isStopping()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
            }
        }
        _model.setRunning(false);
        _model.setStatus("Stopped");
    }

    @Override
    public void setSession(String type, Object store, String session)
            throws StoreException {
    }

    @Override
    public boolean stop() {
        _model.setStopping(true);
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !_model.isRunning();
    }

    public SamlModel getModel() {
        return _model;
    }
}
