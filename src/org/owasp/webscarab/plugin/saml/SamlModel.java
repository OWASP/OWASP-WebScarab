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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.htmlparser.tags.FormTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.ParserException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.FilteredConversationModel;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.parser.Parser;
import org.owasp.webscarab.plugin.AbstractPluginModel;
import org.owasp.webscarab.util.Encoding;
import org.owasp.webscarab.util.MRUCache;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Frank Cornelis
 */
public class SamlModel extends AbstractPluginModel {
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    private final FrameworkModel model;
    private final ConversationModel samlConversationModel;
    private final MRUCache<ConversationID, Document> parsedDocuments;
    private final DocumentBuilder builder;

    public SamlModel(FrameworkModel model) {
        this.model = model;
        this.samlConversationModel = new FilteredConversationModel(model, model.getConversationModel()) {

            @Override
            public boolean shouldFilter(ConversationID id) {
                return !isSAMLMessage(id);
            }
        };
        this.parsedDocuments = new MRUCache<ConversationID, Document>(8);

        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        try {
            this.builder = builderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException ex) {
            throw new RuntimeException("parser config error: " + ex.getMessage(), ex);
        }
    }

    static {
        Init.init();
    }

    /**
     * Mark this conversation message as being a SAML Response.
     *
     * @param id
     * @param encodedSamlResponse
     */
    public void setSAMLResponse(ConversationID id, String encodedSamlResponse) {
        this.model.setConversationProperty(id, "SAML-TYPE", "Response");
        this.model.setConversationProperty(id, "SAML-MESSAGE",
                encodedSamlResponse);
    }

    public void setRelayState(ConversationID id, String relayState) {
        this.model.setConversationProperty(id, "SAML-RELAY-STATE", relayState);
    }

    public String getRelayState(ConversationID id) {
        String relayState = this.model.getConversationProperty(id, "SAML-RELAY-STATE");
        return relayState;
    }

    public String getEncodedSAMLMessage(ConversationID id) {
        String encodedSamlMessage = this.model.getConversationProperty(id, "SAML-MESSAGE");
        String urlDecodedSamlMessage = Encoding.urlDecode(encodedSamlMessage);
        return urlDecodedSamlMessage;
    }

    public String getSAMLMessage(ConversationID id) {
        String samlMessage = this.model.getConversationProperty(id, "SAML-MESSAGE");
        return samlMessage;
    }

    public ConversationID findCorrespondingHTMLFormConversation(ConversationID samlId) {
        ConversationModel conversationModel = this.model.getConversationModel();
        HttpUrl samlHttpUrl = conversationModel.getRequestUrl(samlId);
        int samlConversationIndex = conversationModel.getIndexOfConversation(samlId);
        for (int conversationIndex = samlConversationIndex - 1; conversationIndex >= 0; conversationIndex--) {
            ConversationID id = conversationModel.getConversationAt(conversationIndex);
            Response response = conversationModel.getResponse(id);
            HttpUrl httpUrl = conversationModel.getRequestUrl(id);
            Object parsedContent = Parser.parse(httpUrl, response);
            if (null == parsedContent) {
                continue;
            }
            if (false == parsedContent instanceof org.htmlparser.util.NodeList) {
                continue;
            }
            org.htmlparser.util.NodeList htmlNodeList = (org.htmlparser.util.NodeList) parsedContent;
            org.htmlparser.util.NodeList forms = htmlNodeList.searchFor(FormTag.class);
            try {
                for (NodeIterator ni = forms.elements(); ni.hasMoreNodes();) {
                    FormTag form = (FormTag) ni.nextNode();
                    String formAction = form.getAttribute("action");
                    HttpUrl formActionHttpUrl = new HttpUrl(formAction);
                    if (samlHttpUrl.equals(formActionHttpUrl)) {
                        return id;
                    }
                }
            } catch (ParserException ex) {
                this._logger.log(Level.WARNING, "Looking for forms, got ''{0}''", ex);
            } catch (MalformedURLException ex) {
                this._logger.log(Level.WARNING, "Malformed action url: {0}", ex.getMessage());
            }
        }
        return null;
    }

    public byte[] getResponseContent(ConversationID id) {
        ConversationModel conversationModel = this.model.getConversationModel();
        Response response = conversationModel.getResponse(id);
        byte[] content = response.getContent();
        return content;
    }

    public boolean isOverSSL(ConversationID id) {
        ConversationModel conversationModel = this.model.getConversationModel();
        HttpUrl httpUrl = conversationModel.getRequestUrl(id);
        String scheme = httpUrl.getScheme();
        if ("https".equals(scheme)) {
            return true;
        }
        return false;
    }

    public String getDecodedSAMLMessage(ConversationID id) {
        String encodedSAMLMessage = getEncodedSAMLMessage(id);
        String decodedSAMLMessage = getDecodedSAMLMessage(encodedSAMLMessage);
        return decodedSAMLMessage;
    }

    public String getDecodedSAMLMessage(String encodedSamlMessage) {
        /*
         * Cannot use org.owasp.webscarab.util.Encoding here as SAML tickets not
         * always come with line-breaks.
         */

        String decodedSamlMessage;
        try {
            decodedSamlMessage = new String(Base64.decode(encodedSamlMessage));
        } catch (Base64DecodingException ex) {
            decodedSamlMessage = "[ERROR WHILE DECODING THE BASE64 ENCODED SAML MESSAGE]";
        }

        return decodedSamlMessage;
    }
    public static final int SAML_VERSION_2 = 2;
    public static final int SAML_VERSION_1_1 = 1;

    private Document getSAMLDocument(ConversationID id) {
        Document document = (Document) this.parsedDocuments.get(id);
        if (null != document) {
            return document;
        }

        String encodedSamlMessage = getEncodedSAMLMessage(id);
        String decodedSamlMessage = getDecodedSAMLMessage(encodedSamlMessage);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(decodedSamlMessage.getBytes());

        try {
            document = this.builder.parse(inputStream);
            this.parsedDocuments.put(id, document);
            return document;
        } catch (SAXException ex) {
            return null;
        } catch (IOException ex) {
            return null;
        }
    }

    public int getSAMLVersion(ConversationID id) {
        Document document = getSAMLDocument(id);
        if (null == document) {
            return 0;
        }
        NodeList saml1ResponseNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:protocol", "Response");
        if (0 != saml1ResponseNodeList.getLength()) {
            return SAML_VERSION_1_1;
        }
        NodeList saml2AuthnRequestNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest");
        if (0 != saml2AuthnRequestNodeList.getLength()) {
            return SAML_VERSION_2;
        }
        NodeList saml2ResponseNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "Response");
        if (0 != saml2ResponseNodeList.getLength()) {
            return SAML_VERSION_2;
        }
        return 0;
    }

    public boolean hasDestinationIndication(ConversationID id) {
        Document document = getSAMLDocument(id);
        if (null == document) {
            return false;
        }
        NodeList saml2ResponseNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "Response");
        if (0 != saml2ResponseNodeList.getLength()) {
            return hasDestinationIndicationSaml2Response((Element) saml2ResponseNodeList.item(0));
        }
        NodeList saml2AuthnRequestNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest");
        if (0 != saml2AuthnRequestNodeList.getLength()) {
            return hasDestinationIndicationSaml2AuthnRequest((Element) saml2AuthnRequestNodeList.item(0));
        }
        NodeList saml1ResponseNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:protocol", "Response");
        if (0 != saml1ResponseNodeList.getLength()) {
            return hasDestinationIndicationSaml1Response((Element) saml1ResponseNodeList.item(0));
        }
        return false;
    }

    public static Element findProtocolSignatureElement(Document document) {
        Element documentElement = document.getDocumentElement();
        NodeList documentChildNodes = documentElement.getChildNodes();
        int documentNodeCount = documentChildNodes.getLength();
        for (int nodeIdx = 0; nodeIdx < documentNodeCount; nodeIdx++) {
            Node node = documentChildNodes.item(nodeIdx);
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                Element element = (Element) node;
                if (false == "http://www.w3.org/2000/09/xmldsig#".equals(element.getNamespaceURI())) {
                    continue;
                }
                if (false == "Signature".equals(element.getLocalName())) {
                    continue;
                }
                return element;
            }
        }
        return null;
    }
    
    public static Element findAssertionSignatureElement(Document document) {
        NodeList assertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        if (0 == assertionNodeList.getLength()) {
            assertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion");
            if (0 == assertionNodeList.getLength()) {
                return null;
            }
        }
        Node assertionNode = assertionNodeList.item(0);
        NodeList assertionChildrenNodeList = assertionNode.getChildNodes();
        int assertionChildrenNodeCount = assertionChildrenNodeList.getLength();
        for (int nodeIdx = 0; nodeIdx < assertionChildrenNodeCount; nodeIdx++) {
            Node node = assertionChildrenNodeList.item(nodeIdx);
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                Element element = (Element) node;
                if (false == "http://www.w3.org/2000/09/xmldsig#".equals(element.getNamespaceURI())) {
                    continue;
                }
                if (false == "Signature".equals(element.getLocalName())) {
                    continue;
                }
                return element;
            }
        }
        return null;
    }


    public List<X509Certificate> verifySAMLProtocolSignature(ConversationID id) throws SamlSignatureException {
        Document document = getSAMLDocument(id);
        if (null == document) {
            throw new SamlSignatureException("DOM parser error");
        }
        Element protocolSignatureElement = findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            throw new SamlSignatureException("No protocol XML signature present");
        }
        XMLSignature xmlSignature;
        try {
            xmlSignature = new XMLSignature(protocolSignatureElement, "");
        } catch (XMLSignatureException ex) {
            throw new SamlSignatureException("Invalid protocol XML Signature", ex);
        } catch (XMLSecurityException ex) {
            throw new SamlSignatureException("XML security error", ex);
        }
        KeyInfo keyInfo = xmlSignature.getKeyInfo();
        X509Certificate signingCertificate;
        try {
            signingCertificate = keyInfo.getX509Certificate();
        } catch (KeyResolverException ex) {
            throw new SamlSignatureException("X509 certificate not present", ex);
        }
        boolean signatureValid;
        try {
            signatureValid = xmlSignature.checkSignatureValue(signingCertificate);
        } catch (XMLSignatureException ex) {
            throw new SamlSignatureException("signature error: " + ex.getMessage());
        }
        if (false == signatureValid) {
            throw new SamlSignatureException("invalid");
        }
        List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
        if (false == keyInfo.containsX509Data()) {
            throw new SamlSignatureException("no X509 data in KeyInfo");
        }
        for (int x509DataItemIdx = 0; x509DataItemIdx < keyInfo.lengthX509Data(); x509DataItemIdx++) {
            try {
                X509Data x509Data = keyInfo.itemX509Data(x509DataItemIdx);
                if (false == x509Data.containsCertificate()) {
                    continue;
                }
                int certificateCount = x509Data.lengthCertificate();
                for (int certificateIdx = 0; certificateIdx < certificateCount; certificateIdx++) {
                    XMLX509Certificate xmlX509Certificate = x509Data.itemCertificate(certificateIdx);
                    X509Certificate certificate = xmlX509Certificate.getX509Certificate();
                    certificateChain.add(certificate);
                }
            } catch (XMLSecurityException ex) {
                throw new SamlSignatureException("X509 data error", ex);
            }
        }
        return certificateChain;
    }

    public boolean isSAMLMessage(ConversationID id) {
        return this.model.getConversationProperty(id, "SAML-TYPE") != null;
    }

    public boolean isSAMLResponse(ConversationID id) {
        if ("Response".equals(this.model.getConversationProperty(id, "SAML-TYPE"))) {
            return true;
        }
        return false;
    }

    public ConversationModel getSamlConversationModel() {
        return this.samlConversationModel;
    }

    public String getSAMLType(ConversationID conversationId) {
        String samlType = this.model.getConversationProperty(conversationId,
                "SAML-TYPE");
        return samlType;
    }

    public void setSAMLRequest(ConversationID id, String encodedSamlRequest) {
        this.model.setConversationProperty(id, "SAML-TYPE", "Request");
        this.model.setConversationProperty(id, "SAML-MESSAGE", encodedSamlRequest);
    }

    private boolean hasDestinationIndicationSaml2Response(Element responseElement) {
        if (null != responseElement.getAttributeNode("Destination")) {
            return true;
        }
        NodeList assertionNodeList = responseElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        if (0 == assertionNodeList.getLength()) {
            return false;
        }
        Element assertionElement = (Element) assertionNodeList.item(0);
        NodeList audienceNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Audience");
        if (0 != audienceNodeList.getLength()) {
            return true;
        }
        NodeList subjectConfirmationDataNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "SubjectConfirmationData");
        if (0 == subjectConfirmationDataNodeList.getLength()) {
            return false;
        }
        Element subjectConfirmationDataElement = (Element) subjectConfirmationDataNodeList.item(0);
        if (null != subjectConfirmationDataElement.getAttributeNode("Recipient")) {
            return true;
        }
        if (null != subjectConfirmationDataElement.getAttributeNode("Address")) {
            return true;
        }
        return false;
    }

    private boolean hasDestinationIndicationSaml1Response(Element responseElement) {
        if (null != responseElement.getAttributeNode("Recipient")) {
            return true;
        }
        NodeList assertionNodeList = responseElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion");
        if (0 == assertionNodeList.getLength()) {
            return false;
        }
        Element assertionElement = (Element) assertionNodeList.item(0);
        NodeList audienceNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Audience");
        if (0 != audienceNodeList.getLength()) {
            return true;
        }
        return false;
    }

    private boolean hasDestinationIndicationSaml2AuthnRequest(Element authnRequestElement) {
        if (null != authnRequestElement.getAttributeNode("Destination")) {
            return true;
        }
        return false;
    }

    public boolean protocolSignatureDigestsAssertions(ConversationID id) {
        Document document = getSAMLDocument(id);
        if (null == document) {
            return false;
        }
        Element protocolSignatureElement = findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            return false;
        }

        NodeList saml2AssertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        if (0 != saml2AssertionNodeList.getLength()) {
            try {
                return isDigested(saml2AssertionNodeList, protocolSignatureElement);
            } catch (XMLSignatureException ex) {
                this._logger.log(Level.WARNING, "XML signature error: {0}", ex.getMessage());
            } catch (XMLSecurityException ex) {
                this._logger.log(Level.WARNING, "XML security error: {0}", ex.getMessage());
            }
        }

        NodeList saml1AssertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion");
        if (0 != saml1AssertionNodeList.getLength()) {
            try {
                return isDigested(saml1AssertionNodeList, protocolSignatureElement);
            } catch (XMLSignatureException ex) {
                this._logger.log(Level.WARNING, "XML signature error: {0}", ex.getMessage());
            } catch (XMLSecurityException ex) {
                this._logger.log(Level.WARNING, "XML security error: {0}", ex.getMessage());
            }
        }

        return false;
    }

    private boolean isDigested(NodeList nodeList, Element signatureElement)
            throws XMLSignatureException, XMLSecurityException {
        NodeList referenceNodeList = signatureElement.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Reference");
        Document document = nodeList.item(0).getOwnerDocument();
        Manifest manifest = new Manifest(document);
        VerifyReference[] references = new VerifyReference[referenceNodeList.getLength()];
        for (int referenceIdx = 0; referenceIdx < referenceNodeList.getLength(); referenceIdx++) {
            Element referenceElement = (Element) referenceNodeList.item(referenceIdx);
            VerifyReference reference = new VerifyReference(referenceElement,
                    manifest);
            reference.init();
            references[referenceIdx] = reference;
        }
        return isDigested(nodeList, references);
    }

    private boolean isDigested(NodeList nodes, VerifyReference[] references) {
        for (int idx = 0; idx < nodes.getLength(); idx++) {
            Node node = nodes.item(idx);
            //this._logger.log(Level.FINE, "node name: {0}", node.getLocalName());
            boolean changed = false;
            if (node.getNodeType() == Node.TEXT_NODE) {
                String originalTextValue = node.getNodeValue();
                String changedTextValue = originalTextValue + "foobar";
                node.setNodeValue(changedTextValue);
                changed = false; // need to have impact anyway
                for (int referenceIdx = 0; referenceIdx < references.length; referenceIdx++) {
                    VerifyReference reference = references[referenceIdx];
                    changed |= reference.hasChanged();
                }
                if (false == changed) {
                    return false;
                }
                node.setNodeValue(originalTextValue);
            } else if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;

                NamedNodeMap attributes = element.getAttributes();
                for (int attributeIdx = 0; attributeIdx < attributes.getLength(); attributeIdx++) {
                    Node attributeNode = attributes.item(attributeIdx);
                    String originalAttributeValue = attributeNode.getNodeValue();
                    String changedAttributeValue = originalAttributeValue
                            + "foobar";
                    attributeNode.setNodeValue(changedAttributeValue);
                    for (int referenceIdx = 0; referenceIdx < references.length; referenceIdx++) {
                        VerifyReference reference = references[referenceIdx];
                        changed |= reference.hasChanged();
                    }

                    attributeNode.setNodeValue(originalAttributeValue);
                }
                changed |= isDigested(element.getChildNodes(), references);
            } else if (node.getNodeType() == Node.COMMENT_NODE) {
                // not always digested by the ds:References
            } else {
                throw new RuntimeException("unsupported node type: "
                        + node.getNodeType());
            }
            if (false == changed) {
                return false;
            }
        }
        return true;
    }

    public List<NamedValue> getSAMLAttributes(ConversationID id) {
        List<NamedValue> samlAttributes = new ArrayList<NamedValue>();

        Document document = getSAMLDocument(id);
        if (null == document) {
            return samlAttributes;
        }

        NodeList attributeNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Attribute");
        for (int idx = 0; idx < attributeNodeList.getLength(); idx++) {
            Element attributeElement = (Element) attributeNodeList.item(idx);
            String attributeName = attributeElement.getAttribute("AttributeName");
            NodeList attributeValueNodeList = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AttributeValue");
            if (0 == attributeValueNodeList.getLength()) {
                continue;
            }
            Element attributeValueElement = (Element) attributeValueNodeList.item(0);
            String attributeValue = attributeValueElement.getChildNodes().item(0).getNodeValue();
            NamedValue attribute = new NamedValue(attributeName, attributeValue);
            samlAttributes.add(attribute);
        }

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

    public boolean hasValidityIntervalIndication(ConversationID id) {
        Document document = getSAMLDocument(id);
        if (null == document) {
            return false;
        }

        NodeList saml1AssertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion");
        if (0 != saml1AssertionNodeList.getLength()) {
            Element assertionElement = (Element) saml1AssertionNodeList.item(0);
            NodeList conditionsNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Conditions");
            if (0 != conditionsNodeList.getLength()) {
                Element conditionsElement = (Element) conditionsNodeList.item(0);
                if (null != conditionsElement.getAttributeNode("NotBefore")
                        && null != conditionsElement.getAttributeNode("NotOnOrAfter")) {
                    return true;
                }
            }
        }

        NodeList saml2AssertionNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        if (0 != saml2AssertionNodeList.getLength()) {
            Element assertionElement = (Element) saml2AssertionNodeList.item(0);
            NodeList conditionsNodeList = assertionElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions");
            if (0 != conditionsNodeList.getLength()) {
                Element conditionsElement = (Element) conditionsNodeList.item(0);
                if (null != conditionsElement.getAttributeNode("NotBefore")
                        && null != conditionsElement.getAttributeNode("NotOnOrAfter")) {
                    return true;
                }
            }
        }

        NodeList saml2AuthnRequestNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest");
        if (0 != saml2AuthnRequestNodeList.getLength()) {
            Element authnRequestElement = (Element) saml2AuthnRequestNodeList.item(0);
            NodeList conditionsNodeList = authnRequestElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Conditions");
            if (0 != conditionsNodeList.getLength()) {
                Element conditionsElement = (Element) conditionsNodeList.item(0);
                if (null != conditionsElement.getAttributeNode("NotBefore")
                        && null != conditionsElement.getAttributeNode("NotOnOrAfter")) {
                    return true;
                }
            }
        }

        return false;
    }

    public boolean hasEncryptedAttributes(ConversationID id) {
        Document document = getSAMLDocument(id);
        if (null == document) {
            return false;
        }

        NodeList encryptedAttributeNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAttribute");
        if (0 != encryptedAttributeNodeList.getLength()) {
            return true;
        }
        return false;
    }

    public List getDecryptedAttributes(ConversationID id, String hexKey) throws Exception {
        List samlAttributes = new ArrayList();

        /*
         * We create a new DOM tree as XMLCipher will change the tree.
         */
        String encodedSamlMessage = getEncodedSAMLMessage(id);
        String decodedSamlMessage = getDecodedSAMLMessage(encodedSamlMessage);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(decodedSamlMessage.getBytes());
        Document document = this.builder.parse(inputStream);

        byte[] keyBytes = Hex.decode(hexKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKeySpec);

        NodeList encryptedAttributeNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAttribute");
        for (int encryptedAttributeIdx = 0; encryptedAttributeIdx < encryptedAttributeNodeList.getLength(); encryptedAttributeIdx++) {
            Element encryptedAttributeElement = (Element) encryptedAttributeNodeList.item(encryptedAttributeIdx);
            NodeList encryptedDataNodeList = encryptedAttributeElement.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
            if (1 != encryptedDataNodeList.getLength()) {
                continue;
            }
            Element encryptedDataElement = (Element) encryptedDataNodeList.item(0);
            xmlCipher.doFinal(document, encryptedDataElement);
            NodeList attributeNodeList = encryptedAttributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
            if (1 != attributeNodeList.getLength()) {
                continue;
            }
            Element attributeElement = (Element) attributeNodeList.item(0);
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
