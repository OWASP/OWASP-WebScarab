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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.util.Encoding;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Frank Cornelis
 */
public class WSFederationModel extends AbstractPluginModel {

    private final FrameworkModel model;
    private final ConversationModel wsfedConversationModel;

    public WSFederationModel(FrameworkModel model) {
        this.model = model;

        this.wsfedConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {

            @Override
            public boolean shouldFilter(ConversationID id) {
                return !isWSFederationMessage(id);
            }
        };
    }

    private boolean isWSFederationMessage(ConversationID id) {
        if (null != this.model.getConversationProperty(id, "WTREALM")) {
            return true;
        }
        if (null != this.model.getConversationProperty(id, "WRESULT")) {
            return true;
        }
        return false;
    }

    public ConversationModel getConversationModel() {
        return this.wsfedConversationModel;
    }

    public void setSignInRequestMessage(ConversationID id, String wtrealm) {
        this.model.setConversationProperty(id, "WTREALM", wtrealm);
    }

    public void setSignInResponseMessage(ConversationID id, String wresult) {
        this.model.setConversationProperty(id, "WRESULT", wresult);
    }

    public String getReadableMessageType(ConversationID conversationId) {
        if (null != this.model.getConversationProperty(conversationId, "WTREALM")) {
            return "Sign-In Request";
        }
        if (null != this.model.getConversationProperty(conversationId, "WRESULT")) {
            return "Sign-In Response";
        }
        return "Unknown";
    }

    public List getParameters(ConversationID id) {
        NamedValue[] values = null;

        Request request = this.model.getRequest(id);
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

        if (null == values) {
            return Collections.emptyList();
        }
        for (int idx = 0; idx < values.length; idx++) {
            NamedValue namedValue = values[idx];
            String name = namedValue.getName();
            String value = Encoding.urlDecode(namedValue.getValue());
            namedValue = new NamedValue(name, value);
            values[idx] = namedValue;
        }
        return Arrays.asList(values);
    }

    public byte[] findSAMLAssertion(byte[] wresult) throws ParserConfigurationException, SAXException, IOException, TransformerException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(wresult);
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document document = builder.parse(inputStream);
        Element nsElement = document.createElement("nsElement");
        nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml2",
                "urn:oasis:names:tc:SAML:2.0:assertion");
        Node assertionNode = XPathAPI.selectSingleNode(document, "//saml2:Assertion", nsElement);
        if (null == assertionNode) {
            return null;
        }
        Source source = new DOMSource(assertionNode);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Result result = new StreamResult(outputStream);
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();

        transformer.transform(source, result);
        return outputStream.toByteArray();
    }

    public List getSAMLAttributes(byte[] assertion) throws ParserConfigurationException, SAXException, IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(assertion);
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document document = builder.parse(inputStream);


        List samlAttributes = new ArrayList();
        NodeList attribute2NodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
        for (int idx = 0; idx < attribute2NodeList.getLength(); idx++) {
            Element attributeElement = (Element) attribute2NodeList.item(idx);
            String attributeName = attributeElement.getAttribute("Name");
            NodeList attributeValueNodeList = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
            if (0 == attributeValueNodeList.getLength()) {
                continue;
            }
            Element attributeValueElement = (Element) attributeValueNodeList.item(0);
            String attributeValue = attributeValueElement.getChildNodes().item(0).getNodeValue();
            NamedValue attribute = new NamedValue(attributeName, attributeValue);
            samlAttributes.add(attribute);
        }
        return samlAttributes;
    }
}
