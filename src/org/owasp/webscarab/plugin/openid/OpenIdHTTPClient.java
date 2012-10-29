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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
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

    @Override
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
        if (this.openIdProxyConfig.doRemoveRequestedAttribute()) {
            openIdProxyHeader += removeRequestedAttribute(request);
        }
        if (this.openIdProxyConfig.doAppendAttribute()) {
            openIdProxyHeader += appendAttribute(request);
        }
        if (this.openIdProxyConfig.doRemoveRequestAssociationHandle()) {
            openIdProxyHeader += removeRequestAssociationHandle(request);
        }
        if (this.openIdProxyConfig.doRemoveResponseAssociationHandle()) {
            openIdProxyHeader += removeResponseAssociationHandle(request);
        }

        if (false == openIdProxyHeader.isEmpty()) {
            request.addHeader("X-OpenIDProxy", openIdProxyHeader);
        }

        Response response = this.httpClient.fetchResponse(request);
        return response;
    }

    private NamedValue[] getParameters(Request request) {
        String method = request.getMethod();
        if ("GET".equals(method)) {
            HttpUrl httpUrl = request.getURL();
            String query = httpUrl.getQuery();
            if (null == query) {
                return null;
            }
            NamedValue[] values = NamedValue.splitNamedValues(query, "&", "=");
            return values;
        } else if ("POST".equals(method)) {
            byte[] requestContent = request.getContent();
            if (null == requestContent) {
                return null;
            }
            if (0 == requestContent.length) {
                return null;
            }
            String body = new String(requestContent);
            NamedValue[] values = NamedValue.splitNamedValues(
                    body, "&", "=");
            return values;
        } else {
            return null;
        }
    }

    private String removeSignature(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
        boolean removedSignature = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
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
        updateParameters(values, request);
        return "remove signature;";
    }
    
    private void updateParameters(NamedValue[] values, Request request) {
        updateParameters(values, null, request);
    }

    private void updateParameters(NamedValue[] values, List additionalParameters, Request request) {
        String method = request.getMethod();
        if ("GET".equals(method)) {
            try {
                HttpUrl httpUrl = request.getURL();
                setNewUrl(httpUrl, values, additionalParameters, request);
            } catch (MalformedURLException ex) {
                Logger.getLogger(OpenIdHTTPClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            // POST
            updateRequestPostParameters(values, additionalParameters, request);
        }
    }

    private String corruptSignature(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
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
        updateParameters(values, request);
        return "corrupt signature;";
    }

    private void updateRequestPostParameters(NamedValue[] values, List additionalParameters, Request request) {
        StringBuilder stringBuffer = new StringBuilder();
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
        if (null != additionalParameters) {
            Iterator additionalAttributesIter = additionalParameters.iterator();
            while (additionalAttributesIter.hasNext()) {
                NamedValue namedValue = (NamedValue) additionalAttributesIter.next();
                if (stringBuffer.length() > 1) {
                    stringBuffer.append("&");
                }
                stringBuffer.append(namedValue.getName());
                stringBuffer.append("=");
                stringBuffer.append(namedValue.getValue());
            }
        }
        byte[] content = stringBuffer.toString().getBytes();
        request.setContent(content);
    }

    private void setNewUrl(HttpUrl httpUrl, NamedValue[] values, Request request) throws MalformedURLException {
        setNewUrl(httpUrl, values, null, request);
    }

    private void setNewUrl(HttpUrl httpUrl, NamedValue[] values, List additionalAttributes, Request request) throws MalformedURLException {
        StringBuilder stringBuffer = new StringBuilder("?");
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
        if (null != additionalAttributes) {
            Iterator additionalAttributesIter = additionalAttributes.iterator();
            while (additionalAttributesIter.hasNext()) {
                NamedValue namedValue = (NamedValue) additionalAttributesIter.next();
                stringBuffer.append("&");
                stringBuffer.append(namedValue.getName());
                stringBuffer.append("=");
                stringBuffer.append(namedValue.getValue());
            }
        }
        request.setURL(new HttpUrl(httpUrl.getSHPP() + stringBuffer.toString()));
    }

    private String removeRequestAssociationHandle(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
        // check if OpenID request
        boolean openIdRequest = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if ("openid.mode".equals(name)) {
                if ("checkid_setup".equals(value)) {
                    openIdRequest = true;
                }
                break;
            }
        }
        if (false == openIdRequest) {
            return "";
        }
        // remove assoc_handle
        boolean assocHandleRemoved = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            if ("openid.assoc_handle".equals(name)) {
                values[i] = null;
                assocHandleRemoved = true;
                break;
            }
        }
        if (false == assocHandleRemoved) {
            return "";
        }
        // construct altered response
        updateParameters(values, request);
        return "removed request assoc_handle;";
    }

    private String removeResponseAssociationHandle(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
        // check if OpenID response
        boolean openIdResponse = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if ("openid.mode".equals(name)) {
                if ("id_res".equals(value)) {
                    openIdResponse = true;
                }
                break;
            }
        }
        if (false == openIdResponse) {
            return "";
        }
        // remove assoc_handle
        boolean assocHandleRemoved = false;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            if ("openid.assoc_handle".equals(name)) {
                values[i] = null;
                assocHandleRemoved = true;
                break;
            }
        }
        if (false == assocHandleRemoved) {
            return "";
        }
        // construct altered response
        updateParameters(values, request);
        return "removed response assoc_handle;";
    }

    private String removeRequestedAttribute(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
        // locate the AX alias
        String axAlias = null;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.startsWith("openid.ns.")) {
                if ("http://openid.net/srv/ax/1.0".equals(value)) {
                    axAlias = name.substring("openid.ns.".length());
                    break;
                }
            }
        }
        if (null == axAlias) {
            return "";
        }
        // get set of required AX aliases
        Set requiredAttributeAliases = new HashSet();
        int requiredIdx = -1;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.equals("openid." + axAlias + ".required")) {
                String[] aliases = value.split(",");
                requiredAttributeAliases.addAll(Arrays.asList(aliases));
                requiredIdx = i;
                break;
            }
        }
        // get set of optional AX aliases
        Set optionalAttributeAliases = new HashSet();
        int optionalIdx = -1;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.equals("openid." + axAlias + ".if_available")) {
                String[] aliases = value.split(",");
                optionalAttributeAliases.addAll(Arrays.asList(aliases));
                optionalIdx = i;
                break;
            }
        }
        // remove the attribute
        String attributeAlias = null;
        String attributeType = this.openIdProxyConfig.getRemoveAttributeType();
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.startsWith("openid." + axAlias + ".type.")) {
                if (value.equals(attributeType)) {
                    attributeAlias = name.substring(("openid." + axAlias + ".type.").length());
                    values[i] = null; // remove it
                    break;
                }
            }
        }
        if (null == attributeAlias) {
            return "";
        }
        // remove all references to the attribute alias
        requiredAttributeAliases.remove(attributeAlias);
        Iterator requiredIter = requiredAttributeAliases.iterator();
        String requiredValue = "";
        while (requiredIter.hasNext()) {
            requiredValue += (String) requiredIter.next();
            if (requiredIter.hasNext()) {
                requiredValue += ",";
            }
        }
        values[requiredIdx] = new NamedValue(values[requiredIdx].getName(), requiredValue);

        optionalAttributeAliases.remove(attributeAlias);
        Iterator optionalIter = optionalAttributeAliases.iterator();
        String optionalValue = "";
        while (optionalIter.hasNext()) {
            optionalValue += (String) optionalIter.next();
            if (optionalIter.hasNext()) {
                optionalValue += ",";
            }
        }
        values[optionalIdx] = new NamedValue(values[optionalIdx].getName(), optionalValue);

        updateParameters(values, request);
        return "removed attribute request;";
    }

    private String appendAttribute(Request request) {
        NamedValue[] values = getParameters(request);
        if (null == values) {
            return "";
        }
        // check if openid response
        boolean response = false;
        for (int idx = 0; idx < values.length; idx++) {
            String name = values[idx].getName();
            String value = Encoding.urlDecode(values[idx].getValue());
            if ("openid.mode".equals(name)) {
                if ("id_res".equals(value)) {
                    response = true;
                    break;
                }
            }
        }
        if (false == response) {
            return "";
        }
        // check if AX response is present
        String axAlias = null;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.startsWith("openid.ns.")) {
                if ("http://openid.net/srv/ax/1.0".equals(value)) {
                    axAlias = name.substring("openid.ns.".length());
                    break;
                }
            }
        }
        List additionalParameters = new LinkedList();
        if (null == axAlias) {
            axAlias = "ax";
            additionalParameters.add(new NamedValue("openid.ns." + axAlias, "http://openid.net/srv/ax/1.0"));
            additionalParameters.add(new NamedValue("openid." + axAlias + ".mode", "fetch_response"));
        }
        String attributeAlias = this.openIdProxyConfig.getAppendAttributeAlias();
        String attributeType = this.openIdProxyConfig.getAppendAttributeType();
        String attributeValue = this.openIdProxyConfig.getAppendAttributeValue();
        additionalParameters.add(new NamedValue("openid." + axAlias + ".type." + attributeAlias, Encoding.urlEncode(attributeType)));
        additionalParameters.add(new NamedValue("openid." + axAlias + ".value." + attributeAlias, Encoding.urlEncode(attributeValue)));
        
        updateParameters(values, additionalParameters, request);
        return "add attribute response;";
    }
}
