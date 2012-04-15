/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 Frank Cornelis <info@frankcornelis.be>
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
package test.unit.org.owasp.webscarab.plugin.saml;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.Result;
import java.io.StringWriter;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.Source;
import org.apache.xml.security.Init;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Frank Cornelis
 */
public class SamlTest {

    private static final Log LOG = LogFactory.getLog(SamlTest.class);

    @BeforeClass
    public static void beforeClass() {
        Init.init();
    }

    @Test
    public void testEncryptionAES() throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        SecretKey secretKey = keygen.generateKey();

        LOG.debug("secret key algo: " + secretKey.getAlgorithm());
        LOG.debug("secret key format: " + secretKey.getFormat());

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        LOG.debug("cipher provider: " + cipher.getProvider().getName());
        byte[] result = cipher.doFinal("hello world".getBytes());
        assertNotNull(result);

        byte[] encodedSecretKey = secretKey.getEncoded();
        LOG.debug("encoded secret key size: " + encodedSecretKey.length * 8);

        // decrypt
        cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = new SecretKeySpec(encodedSecretKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedResult = cipher.doFinal(result);
        assertEquals("hello world", new String(decryptedResult));
    }

    @Test
    public void testEncryptedXML() throws Exception {
        // setup
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        builderFactory.setNamespaceAware(true);
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        Document document = builder.parse(SamlTest.class.getResourceAsStream("/test-saml-response-encrypted-attribute.xml"));

        NodeList nodeList = document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAttribute");
        assertEquals(1, nodeList.getLength());
        Element encryptedAttributeElement = (Element) nodeList.item(0);
        NodeList encryptedDataNodeList = encryptedAttributeElement.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData");
        assertEquals(1, encryptedDataNodeList.getLength());
        Element encryptedDataElement = (Element) encryptedDataNodeList.item(0);
        Init.init();
        XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.AES_128);
        String aes128HexStr = "2a1e3d83f475ec3c007f487c5150a5f2";
        byte[] aes128Bytes = Hex.decode(aes128HexStr);
        SecretKeySpec secretKeySpec = new SecretKeySpec(aes128Bytes, "AES");
        xmlCipher.init(XMLCipher.DECRYPT_MODE, secretKeySpec);
        xmlCipher.doFinal(document, encryptedDataElement);
        LOG.debug("decrypted attribute: " + toString(encryptedAttributeElement));
        NodeList attributeNodeList = encryptedAttributeElement.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Attribute");
        assertEquals(1, attributeNodeList.getLength());
    }

    private String toString(Node node) throws TransformerConfigurationException, TransformerException {
        Source source = new DOMSource(node);
        StringWriter stringWriter = new StringWriter();
        Result result = new StreamResult(stringWriter);
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.transform(source, result);
        return stringWriter.getBuffer().toString();
    }
}
