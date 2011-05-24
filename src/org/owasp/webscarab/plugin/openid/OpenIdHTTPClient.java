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

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author Frank Cornelis
 */
public class OpenIdHTTPClient implements HTTPClient {

    private final HTTPClient httpClient;
    private final OpenIdProxyConfig openIdProxyConfig;

    public OpenIdHTTPClient(HTTPClient httpClient, OpenIdProxyConfig openIdProxyConfig) {
        this.httpClient = httpClient;
        this.openIdProxyConfig = openIdProxyConfig;
    }

    public Response fetchResponse(Request request) throws IOException {
        if (false == this.openIdProxyConfig.doSomething()) {
            Response response = this.httpClient.fetchResponse(request);
            return response;
        }

        String openIdProxyHeader = "";

        if (this.openIdProxyConfig.doCorruptSignature()) {
            openIdProxyHeader += corruptSignature(request);
        }
        if (this.openIdProxyConfig.doRemoveSignature()) {
            openIdProxyHeader += removeSignature(request);
        }

        if (false == openIdProxyHeader.isEmpty()) {
            request.addHeader("X-OpenIDProxy", openIdProxyHeader);
        }

        Response response = this.httpClient.fetchResponse(request);
        return response;
    }

    private String removeSignature(Request request) {
        HttpUrl httpUrl = request.getURL();
        String query = httpUrl.getQuery();
        if (null == query) {
            return "";
        }
        NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
        boolean removedSignature = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if ("openid.sig".equals(name)) {
                values[i] = null;
                removedSignature = true;
            }
            if ("openid.signed".equals(name)) {
                values[i] = null;
                removedSignature = true;
            }
        }
        if (false == removedSignature) {
            return "";
        }
        try {
            setNewUrl(httpUrl, values, request);
        } catch (MalformedURLException ex) {
            Logger.getLogger(OpenIdHTTPClient.class.getName()).log(Level.SEVERE, null, ex);
            return "";
        }
        return "remove signature;";
    }

    private String corruptSignature(Request request) {
        HttpUrl httpUrl = request.getURL();
        String query = httpUrl.getQuery();
        if (null == query) {
            return "";
        }
        NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
        boolean corruptedSignature = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if ("openid.sig".equals(name)) {
                byte[] decodedSignature = Base64.decode(value);
                decodedSignature[0]++;
                String corruptEncodedSignature = new String(Base64.encode(decodedSignature));
                values[i] = new NamedValue(name, corruptEncodedSignature);
                corruptedSignature = true;
                break;
            }
        }
        if (false == corruptedSignature) {
            return "";
        }
        try {
            setNewUrl(httpUrl, values, request);
        } catch (MalformedURLException ex) {
            Logger.getLogger(OpenIdHTTPClient.class.getName()).log(Level.SEVERE, null, ex);
            return "";
        }
        return "corrupt signature;";
    }

    public void setNewUrl(HttpUrl httpUrl, NamedValue[] values, Request request) throws MalformedURLException {
        StringBuffer stringBuffer = new StringBuffer("?");
        for (int i = 0; i < values.length; i++) {
            if (null == values[i]) {
                continue;
            }
            if (stringBuffer.length() > 1) {
                stringBuffer.append("&");
            }
            stringBuffer.append(values[i].getName());
            stringBuffer.append("=");
            stringBuffer.append(values[i].getValue());
        }
        request.setURL(new HttpUrl(httpUrl.getSHPP() + stringBuffer.toString()));
    }
}
