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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.owasp.webscarab.httpclient.HTTPClient;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.util.Encoding;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 *
 * @author Frank Cornelis
 */
public class SamlHTTPClient implements HTTPClient {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final HTTPClient in;
    private final SamlProxyConfig samlProxyConfig;

    public SamlHTTPClient(HTTPClient in, SamlProxyConfig samlProxyConfig) {
        this.in = in;
        this.samlProxyConfig = samlProxyConfig;
    }

    public Response fetchResponse(Request request) throws IOException {
        /*
         * We want a very fast fall-through in case nothing needs to be done.
         */
        if (false == this.samlProxyConfig.doSomething()) {
            Response response = this.in.fetchResponse(request);
            return response;
        }

        changeSamlResponse(request);

        String samlProxyHeader = "";
        if (this.samlProxyConfig.doReplay()) {
            samlProxyHeader += "replayed;";
        }
        
        if (this.samlProxyConfig.doInjectAttribute()) {
            samlProxyHeader += "injected attribute;";
        }
        if (this.samlProxyConfig.doInjectSubject()) {
            samlProxyHeader += "injected subject;";
        }
        if (this.samlProxyConfig.doInjectPublicDoctype()) {
            samlProxyHeader += "injected public doctype;";
        }
        if (this.samlProxyConfig.doInjectRelayState()) {
            samlProxyHeader += "injected relay state;";
        }
        
        if (this.samlProxyConfig.doSignSamlMessage()) {
            samlProxyHeader += "sign;";
        } else if (this.samlProxyConfig.doRemoveSignature()) {
            samlProxyHeader += "removed signature;";
        } else {
            if (this.samlProxyConfig.doCorruptSignature()) {
                samlProxyHeader += "corrupted signature;";
            }
            if (this.samlProxyConfig.doInjectRemoteReference()) {
                samlProxyHeader += "injected remote reference;";
            }
        }

        if (samlProxyHeader.length() > 0) {
            request.addHeader("X-SAMLProxy", samlProxyHeader);
        }

        Response response = this.in.fetchResponse(request);
        return response;
    }

    private void changeSamlResponse(Request request) {
        String method = request.getMethod();
        if (false == "POST".equals(method)) {
            return;
        }
        String contentType = request.getHeader("Content-Type");
        if (null == contentType) {
            return;
        }
        if (false == "application/x-www-form-urlencoded".equals(contentType)) {
            return;
        }
        byte[] content = request.getContent();
        if (null == content) {
            return;
        }
        if (0 == content.length) {
            return;
        }
        String body = new String(content);
        NamedValue[] namedValues = NamedValue.splitNamedValues(
                body, "&", "=");
        boolean samlResponseMessage = false;
        for (int idx = 0; idx < namedValues.length; idx++) {
            if ("RelayState".equals(namedValues[idx].getName())) {
                if (this.samlProxyConfig.doInjectRelayState()) {
                    String newRelayState = getInjectedRelayState();
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newRelayState);
                }
            }

            if (false == "SAMLResponse".equals(namedValues[idx].getName())) {
                continue;
            }
            samlResponseMessage = true;

            try {
                if (this.samlProxyConfig.doReplay()) {
                    String newSamlResponse = replaySamlResponse();
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                }

                if (this.samlProxyConfig.doInjectAttribute()) {
                    String newSamlResponse = injectAttribute(namedValues[idx].getValue());
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                }
                if (this.samlProxyConfig.doInjectSubject()) {
                    String newSamlResponse = injectSubject(namedValues[idx].getValue());
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                }
                if (this.samlProxyConfig.doInjectPublicDoctype()) {
                    String newSamlResponse = injectPublicDoctype(namedValues[idx].getValue());
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                }
                
                if (this.samlProxyConfig.doSignSamlMessage()) {
                    String newSamlResponse = signSamlMessage(namedValues[idx].getValue());
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                } else if (this.samlProxyConfig.doRemoveSignature()) {
                    String newSamlResponse = removeSamlResponseSignature(namedValues[idx].getValue());
                    namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                } else {
                    if (this.samlProxyConfig.doCorruptSignature()) {
                        String newSamlResponse = corruptSamlResponseSignature(namedValues[idx].getValue());
                        namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                    }
                    if (this.samlProxyConfig.doInjectRemoteReference()) {
                        String newSamlResponse = injectRemoteReference(namedValues[idx].getValue());
                        namedValues[idx] = new NamedValue(namedValues[idx].getName(), newSamlResponse);
                    }
                }
            } catch (Exception ex) {
                this._logger.log(Level.WARNING, "could not corrupt the SAML Response signature: {0}", ex.getMessage());
                continue;
            }
        }
        if (false == samlResponseMessage) {
            return;
        }

        StringBuffer newBody = new StringBuffer();
        for (int idx = 0; idx < namedValues.length; idx++) {
            NamedValue namedValue = namedValues[idx];
            if (0 != newBody.length()) {
                newBody.append("&");
            }
            newBody.append(namedValue.getName());
            newBody.append("=");
            newBody.append(namedValue.getValue());
        }
        request.setContent(newBody.toString().getBytes());
    }

    private String corruptSamlResponseSignature(String samlResponse) throws TransformerConfigurationException, TransformerException, IOException, ParserConfigurationException, SAXException, Base64DecodingException {
        Document document = parseDocument(samlResponse);

        Element protocolSignatureElement = SamlModel.findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            this._logger.warning("no XML signature found");
            return samlResponse;
        }

        NodeList referenceNodeList = protocolSignatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Reference");
        if (0 == referenceNodeList.getLength()) {
            this._logger.warning("no XMLDSig Reference element present");
            return samlResponse;
        }
        /*
         * We simply corrupt the first ds:Reference that we encounter.
         */
        Element referenceElement = (Element) referenceNodeList.item(0);

        NodeList digestValueNodeList = referenceElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "DigestValue");
        Element digestValueElement = (Element) digestValueNodeList.item(0);
        String digestValue = digestValueElement.getTextContent();
        digestValue = "12345678" + digestValue;
        digestValueElement.setTextContent(digestValue);

        return outputDocument(document);
    }

    private String removeSamlResponseSignature(String samlResponse) throws IOException, ParserConfigurationException, SAXException, TransformerConfigurationException, TransformerException, Base64DecodingException {
        Document document = parseDocument(samlResponse);
        Element protocolSignatureElement = SamlModel.findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            return samlResponse;
        }
        protocolSignatureElement.getParentNode().removeChild(protocolSignatureElement);

        return outputDocument(document);
    }

    private String outputDocument(Document document) throws TransformerConfigurationException, TransformerException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Result result = new StreamResult(outputStream);
        Transformer xformer = TransformerFactory.newInstance().newTransformer();
        Source source = new DOMSource(document);
        xformer.transform(source, result);

        String encodedChangedSamlResponse = Base64.encode(outputStream.toByteArray());
        return Encoding.urlEncode(encodedChangedSamlResponse);
    }

    private Document parseDocument(String samlResponse) throws IOException, ParserConfigurationException, SAXException, Base64DecodingException {
        byte[] decodedSamlResponse = Base64.decode(Encoding.urlDecode(samlResponse));

        ByteArrayInputStream inputStream = new ByteArrayInputStream(decodedSamlResponse);
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document document = builder.parse(inputStream);
        return document;
    }

    private String replaySamlResponse() {
        String replayedSamlResponse = this.samlProxyConfig.getReplaySamlResponse();
        return replayedSamlResponse;
    }

    private String injectRemoteReference(String samlResponse) throws IOException, ParserConfigurationException, SAXException, Base64DecodingException, TransformerConfigurationException, TransformerException {
        Document document = parseDocument(samlResponse);

        Element protocolSignatureElement = SamlModel.findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            this._logger.warning("no XML signature found");
            return samlResponse;
        }

        NodeList signedInfoNodeList = protocolSignatureElement.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "SignedInfo");
        if (0 == signedInfoNodeList.getLength()) {
            this._logger.warning("no SignedInfo present in XML signature");
            return samlResponse;
        }
        Element signedInfoElement = (Element) signedInfoNodeList.item(0);

        String namespacePrefix = protocolSignatureElement.getPrefix();
        if (null == namespacePrefix) {
            namespacePrefix = "";
        } else {
            namespacePrefix = namespacePrefix + ":";
        }

        Element referenceElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", namespacePrefix + "Reference");
        signedInfoElement.appendChild(referenceElement);
        String remoteReference = this.samlProxyConfig.getRemoteReference();
        referenceElement.setAttributeNS(null, "URI", remoteReference);
        Element digestMethodElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", namespacePrefix + "DigestMethod");
        referenceElement.appendChild(digestMethodElement);
        digestMethodElement.setAttributeNS(null, "Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        Element digestValueElement = document.createElementNS("http://www.w3.org/2000/09/xmldsig#", namespacePrefix + "DigestValue");
        referenceElement.appendChild(digestValueElement);
        digestValueElement.appendChild(document.createTextNode("12345678"));

        return outputDocument(document);
    }

    private String injectAttribute(String samlResponse) throws IOException, ParserConfigurationException, SAXException, Base64DecodingException, TransformerConfigurationException, TransformerException {
        Document document = parseDocument(samlResponse);

        String injectionAttributeName = this.samlProxyConfig.getInjectionAttributeName();
        String injectionAttributeValue = this.samlProxyConfig.getInjectionAttributeValue();

        NodeList attributeNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Attribute");
        for (int idx = 0; idx < attributeNodeList.getLength(); idx++) {
            Element attributeElement = (Element) attributeNodeList.item(idx);
            String attributeName = attributeElement.getAttribute("AttributeName");
            if (attributeName.equals(injectionAttributeName)) {
                NodeList attributeValueNodeList = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "AttributeValue");
                for (int valueIdx = 0; valueIdx < attributeValueNodeList.getLength(); valueIdx++) {
                    Element attributeValueElement = (Element) attributeValueNodeList.item(valueIdx);
                    attributeValueElement.getChildNodes().item(0).setNodeValue(injectionAttributeValue);
                }
            }
        }

        NodeList attribute2NodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
        for (int idx = 0; idx < attribute2NodeList.getLength(); idx++) {
            Element attributeElement = (Element) attribute2NodeList.item(idx);
            String attributeName = attributeElement.getAttribute("Name");
            if (attributeName.equals(injectionAttributeName)) {
                NodeList attributeValueNodeList = attributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "AttributeValue");
                for (int valueIdx = 0; valueIdx < attributeValueNodeList.getLength(); valueIdx++) {
                    Element attributeValueElement = (Element) attributeValueNodeList.item(valueIdx);
                    attributeValueElement.getChildNodes().item(0).setNodeValue(injectionAttributeValue);
                }
            }
        }

        return outputDocument(document);
    }

    private String getInjectedRelayState() {
        String injectionRelayState = this.samlProxyConfig.getRelayState();
        return Encoding.urlEncode(injectionRelayState);
    }

    private String injectSubject(String samlResponse) throws IOException, ParserConfigurationException, SAXException, Base64DecodingException, TransformerConfigurationException, TransformerException {
        Document document = parseDocument(samlResponse);

        String injectionSubject = this.samlProxyConfig.getInjectionSubject();

        NodeList subjectNodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Subject");
        for (int subjectIdx = 0; subjectIdx < subjectNodeList.getLength(); subjectIdx++) {
            Element subjectElement = (Element) subjectNodeList.item(subjectIdx);
            NodeList nameIdentifierNodeList = subjectElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "NameIdentifier");
            if (0 != nameIdentifierNodeList.getLength()) {
                nameIdentifierNodeList.item(0).getChildNodes().item(0).setNodeValue(injectionSubject);
            }
        }

        NodeList subject2NodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Subject");
        for (int subjectIdx = 0; subjectIdx < subject2NodeList.getLength(); subjectIdx++) {
            Element subjectElement = (Element) subject2NodeList.item(subjectIdx);
            NodeList nameIDNodeList = subjectElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
            if (0 != nameIDNodeList.getLength()) {
                nameIDNodeList.item(0).getChildNodes().item(0).setNodeValue(injectionSubject);
            }
        }

        return outputDocument(document);
    }

    private String injectPublicDoctype(String samlResponse) throws Base64DecodingException {
        String dtdUri = this.samlProxyConfig.getDtdUri();
        byte[] decodedSamlResponse = Base64.decode(Encoding.urlDecode(samlResponse));
        String newDecodedSamlResponse = "<!DOCTYPE SomeElement SYSTEM \"" + dtdUri + "\">" + new String(decodedSamlResponse);
        String newSamlResponse = Encoding.urlEncode(Base64.encode(newDecodedSamlResponse.getBytes()));
        return newSamlResponse;
    }

    private String signSamlMessage(String samlResponse) throws IOException, ParserConfigurationException, SAXException, Base64DecodingException, TransformerConfigurationException, TransformerException, XMLSecurityException {
        Document document = parseDocument(samlResponse);
        Element protocolSignatureElement = SamlModel.findProtocolSignatureElement(document);
        if (null == protocolSignatureElement) {
            return samlResponse;
        }
        protocolSignatureElement.getParentNode().removeChild(protocolSignatureElement);

        XMLSignature xmlSignature = new XMLSignature(document, null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        document.getDocumentElement().insertBefore(xmlSignature.getElement(), document.getDocumentElement().getFirstChild());
        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        xmlSignature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
        
        KeyStore.PrivateKeyEntry privateKeyEntry = this.samlProxyConfig.getPrivateKeyEntry();
        
        KeyInfo keyInfo = xmlSignature.getKeyInfo();
        X509Data x509Data = new X509Data(document);
        Certificate[] certificateChain = privateKeyEntry.getCertificateChain();
        for (int certIdx = 0; certIdx < certificateChain.length; certIdx++) {
            Certificate certificate = certificateChain[certIdx];
            x509Data.addCertificate((X509Certificate) certificate);
        }
        keyInfo.add(x509Data);
        
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        xmlSignature.sign(privateKey);
        
        return outputDocument(document);
    }
}
