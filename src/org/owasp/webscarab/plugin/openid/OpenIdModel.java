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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import javax.crypto.spec.DHParameterSpec;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.association.DiffieHellmanSession;
import org.openid4java.message.AssociationRequest;
import org.openid4java.message.AssociationResponse;
import org.openid4java.message.ParameterList;
import org.owasp.webscarab.httpclient.HTTPClientFactory;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.util.Encoding;

/**
 *
 * @author Frank Cornelis
 */
public class OpenIdModel extends AbstractPluginModel {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final FrameworkModel model;
    private final ConversationModel openIdConversationModel;

    public OpenIdModel(FrameworkModel model) {
        this.model = model;
        this.openIdConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {

            @Override
            public boolean shouldFilter(ConversationID id) {
                return !isOpenIDMessage(id);
            }
        };
    }

    public void setOpenIDMessage(ConversationID id, String namespace) {
        this.model.setConversationProperty(id, "OPENID", namespace);
    }

    public boolean isOpenIDMessage(ConversationID id) {
        return this.model.getConversationProperty(id, "OPENID") != null;
    }

    public ConversationModel getOpenIDConversationModel() {
        return this.openIdConversationModel;
    }

    public void setOpenIDMessageType(ConversationID id, String messageType) {
        this.model.setConversationProperty(id, "OPENID_MODE", messageType);
    }

    public String getReadableOpenIDMessageType(ConversationID id) {
        String openIdMode = this.model.getConversationProperty(id, "OPENID_MODE");
        if (null == openIdMode) {
            return "Unknown";
        }
        if ("checkid_setup".equals(openIdMode)) {
            return "Request";
        }
        if ("id_res".equals(openIdMode)) {
            return "Response";
        }
        return "Unknown";
    }

    public List getParameters(ConversationID id) {
        List parameters = new LinkedList();
        Request request = this.model.getRequest(id);
        NamedValue[] values = null;
        String method = request.getMethod();
        if ("GET".equals(method)) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                values = NamedValue.splitNamedValues(query, "&", "=");
            }
        } else if ("POST".equals(method)) {
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
                if (name.startsWith("openid.")) {
                    NamedValue parameter = new NamedValue(name, value);
                    parameters.add(parameter);
                }
            }
        }
        return parameters;
    }

    public List getAXFetchRequestAttributes(ConversationID id) {
        List attributes = new LinkedList();
        Request request = this.model.getRequest(id);
        String method = request.getMethod();
        NamedValue[] values = null;
        if ("GET".equals(method)) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                values = NamedValue.splitNamedValues(query, "&", "=");
            }
        } else if ("POST".equals(method)) {
            byte[] requestContent = request.getContent();
            if (requestContent != null && requestContent.length > 0) {
                String body = new String(requestContent);
                values = NamedValue.splitNamedValues(
                        body, "&", "=");
            }
        }
        if (null != values) {
            // first locate the AX extension
            String alias = null;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid.ns.")) {
                    if ("http://openid.net/srv/ax/1.0".equals(value)) {
                        alias = name.substring("openid.ns.".length());
                        break;
                    }
                }
            }
            if (null == alias) {
                return attributes;
            }
            _logger.info("AX alias: " + alias);
            // check the AX mode
            boolean isFetchRequest = false;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".mode")) {
                    if ("fetch_request".equals(value)) {
                        isFetchRequest = true;
                        break;
                    }
                }
            }
            if (false == isFetchRequest) {
                return attributes;
            }
            // required aliases
            Set requiredAliases = new HashSet();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".required")) {
                    String[] aliases = value.split(",");
                    requiredAliases.addAll(Arrays.asList(aliases));
                    break;
                }
            }
            // optional aliases
            Set optionalAliases = new HashSet();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".if_available")) {
                    String[] aliases = value.split(",");
                    optionalAliases.addAll(Arrays.asList(aliases));
                    break;
                }
            }
            // get the fetch request attributes
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid." + alias + ".type.")) {
                    String attributeAlias = name.substring(("openid." + alias + ".type.").length());
                    boolean requiredAttribute = requiredAliases.contains(attributeAlias);
                    boolean optionalAttribute = optionalAliases.contains(attributeAlias);
                    AXFetchRequestAttribute attribute = new AXFetchRequestAttribute(value, attributeAlias, requiredAttribute, optionalAttribute);
                    attributes.add(attribute);
                }
            }
        }
        return attributes;
    }

    public List getAXFetchResponseAttributes(ConversationID id) {
        List attributes = new LinkedList();
        Request request = this.model.getRequest(id);
        String method = request.getMethod();
        NamedValue[] values = null;
        if ("GET".equals(method)) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                values = NamedValue.splitNamedValues(query, "&", "=");
            }
        } else if ("POST".equals(method)) {
            byte[] requestContent = request.getContent();
            if (requestContent != null && requestContent.length > 0) {
                String body = new String(requestContent);
                values = NamedValue.splitNamedValues(
                        body, "&", "=");
            }
        }
        if (null != values) {
            // first locate the AX extension
            String alias = null;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid.ns.")) {
                    if ("http://openid.net/srv/ax/1.0".equals(value)) {
                        alias = name.substring("openid.ns.".length());
                        break;
                    }
                }
            }
            if (null == alias) {
                return attributes;
            }
            _logger.info("AX alias: " + alias);
            // check the AX mode
            boolean isFetchResponse = false;
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid." + alias + ".mode")) {
                    if ("fetch_response".equals(value)) {
                        isFetchResponse = true;
                        break;
                    }
                }
            }
            if (false == isFetchResponse) {
                return attributes;
            }
            // signed aliases
            Set signedAliases = new HashSet();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.equals("openid.signed")) {
                    String[] aliases = value.split(",");
                    signedAliases.addAll(Arrays.asList(aliases));
                    break;
                }
            }
            // get the fetch response attributes
            Map attributeMap = new HashMap();
            for (int i = 0; i < values.length; i++) {
                String name = values[i].getName();
                String value = Encoding.urlDecode(values[i].getValue());
                if (name.startsWith("openid." + alias + ".type.")) {
                    String attributeAlias = name.substring(("openid." + alias + ".type.").length());
                    AXFetchResponseAttribute attribute = (AXFetchResponseAttribute) attributeMap.get(attributeAlias);
                    if (null == attribute) {
                        attribute = new AXFetchResponseAttribute(attributeAlias);
                        attributeMap.put(attributeAlias, attribute);
                    }
                    attribute.setAttributeType(value);
                } else if (name.startsWith("openid." + alias + ".value.")) {
                    String attributeAlias = name.substring(("openid." + alias + ".value.").length());
                    AXFetchResponseAttribute attribute = (AXFetchResponseAttribute) attributeMap.get(attributeAlias);
                    if (null == attribute) {
                        attribute = new AXFetchResponseAttribute(attributeAlias);
                        attributeMap.put(attributeAlias, attribute);
                    }
                    attribute.setValue(value);
                }
            }
            attributes.addAll(attributeMap.values());
            // check attribute signing
            Iterator attributeIterator = attributes.iterator();
            while (attributeIterator.hasNext()) {
                AXFetchResponseAttribute attribute = (AXFetchResponseAttribute) attributeIterator.next();
                if (signedAliases.contains(alias + ".type." + attribute.getAlias())
                        && signedAliases.contains(alias + ".value." + attribute.getAlias())) {
                    attribute.setSigned(true);
                }
            }
        }
        return attributes;
    }

    public PAPEResponse getPAPEResponse(ConversationID id) {
        Request request = this.model.getRequest(id);
        String method = request.getMethod();
        NamedValue[] values = null;
        if ("GET".equals(method)) {
            HttpUrl url = request.getURL();
            String query = url.getQuery();
            if (null != query) {
                values = NamedValue.splitNamedValues(query, "&", "=");
            }
        } else if ("POST".equals(method)) {
            byte[] requestContent = request.getContent();
            if (requestContent != null && requestContent.length > 0) {
                String body = new String(requestContent);
                values = NamedValue.splitNamedValues(
                        body, "&", "=");
            }
        }
        if (null == values) {
            return null;
        }
        // first locate the PAPE extension
        String alias = null;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.startsWith("openid.ns.")) {
                if ("http://specs.openid.net/extensions/pape/1.0".equals(value)) {
                    alias = name.substring("openid.ns.".length());
                    break;
                }
            }
        }
        if (null == alias) {
            return null;
        }
        // signed aliases
        Set signedAliases = new HashSet();
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.equals("openid.signed")) {
                String[] aliases = value.split(",");
                signedAliases.addAll(Arrays.asList(aliases));
                break;
            }
        }
        PAPEResponse papeResponse = new PAPEResponse();
        boolean signed = true;
        for (int i = 0; i < values.length; i++) {
            String name = values[i].getName();
            String value = Encoding.urlDecode(values[i].getValue());
            if (name.startsWith("openid." + alias)) {
                String expectedSignedAlias = name.substring("openid.".length());
                if (false == signedAliases.contains(expectedSignedAlias)) {
                    signed = false;
                }
            }
            if (name.equals("openid." + alias + ".auth_time")) {
                papeResponse.setAuthenticationTime(value);
            } else if (name.equals("openid." + alias + ".auth_policies")) {
                String[] authPolicies = value.split(" ");
                Set authPoliciesSet = new HashSet(Arrays.asList(authPolicies));
                if (authPoliciesSet.contains("http://schemas.openid.net/pape/policies/2007/06/phishing-resistant")) {
                    papeResponse.setPhishingResistant(true);
                }
                if (authPoliciesSet.contains("http://schemas.openid.net/pape/policies/2007/06/multi-factor")) {
                    papeResponse.setMultiFactor(true);
                }
                if (authPoliciesSet.contains("http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical")) {
                    papeResponse.setMultiFactorPhysical(true);
                }
            }
        }
        if (false == signedAliases.contains("ns." + alias)) {
            signed = false;
        }
        papeResponse.setSigned(signed);
        return papeResponse;
    }

    public Association establishAssociation(String opUrl, AssociationSessionType associationSessionType) throws Exception {
        DiffieHellmanSession dhSession;
        if (null != associationSessionType.getHAlgorithm()) {
            // Diffie-Hellman
            DHParameterSpec dhParameterSpec = DiffieHellmanSession.getDefaultParameter();
            dhSession = DiffieHellmanSession.create(associationSessionType,
                    dhParameterSpec);
        } else {
            dhSession = null;
        }
        AssociationRequest associationRequest = AssociationRequest.createAssociationRequest(associationSessionType, dhSession);
        Request request = new Request();
        request.setMethod("POST");
        request.setURL(new HttpUrl(opUrl));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");

        StringBuilder body = new StringBuilder();
        Map parameters = associationRequest.getParameterMap();
        Set parameterEntries = parameters.entrySet();
        Iterator parameterIterator = parameterEntries.iterator();
        while (parameterIterator.hasNext()) {
            if (0 != body.length()) {
                body.append("&");
            }
            Map.Entry parameterEntry = (Map.Entry) parameterIterator.next();
            body.append(parameterEntry.getKey());
            body.append("=");
            body.append(Encoding.urlEncode((String)parameterEntry.getValue()));
        }
        request.setHeader("Content-Length", Integer.toString(body.length()));
        request.setContent(body.toString().getBytes());

        Response response = HTTPClientFactory.getInstance().fetchResponse(request);
        if (false == "200".equals(response.getStatus())) {
            throw new RuntimeException("invalid status return code: " + response.getStatus());
        }

        byte[] responseContent = response.getContent();
        ParameterList responseParameterList = ParameterList.createFromKeyValueForm(new String(responseContent));
        AssociationResponse associationResponse = AssociationResponse.createAssociationResponse(responseParameterList);

        Association association = associationResponse.getAssociation(dhSession);
        return association;
    }

    public boolean isOpenIDRequestMessage(ConversationID id) {
        String openIdMode = this.model.getConversationProperty(id, "OPENID_MODE");
        if (null == openIdMode) {
            return false;
        }
        if ("checkid_setup".equals(openIdMode)) {
            return true;
        }
        return false;
    }

    public String getOPUrl(ConversationID id) {
        if (false == isOpenIDRequestMessage(id)) {
            return null;
        }
        HttpUrl httpUrl = this.model.getRequestUrl(id);
        return httpUrl.getSHPP();
    }
}
