/*
 * Schema.java
 *
 * Created on 14 September 2005, 10:25
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.wsdl.Definition;
import javax.xml.namespace.QName;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author rdawes
 */
public class Schema {
    
    public final static String SOAP_NS =
            "http://schemas.xmlsoap.org/soap/envelope/";
    public final static String XSD_NS =
            "http://www.w3.org/2001/XMLSchema";
    public final static String XSI_NS =
            "http://www.w3.org/2001/XMLSchema-instance";
    
    private Map namespaces;
    
    private Map types = new HashMap();
    
    public Schema(Map namespaces, Element[] elements) {
        this.namespaces = new HashMap(namespaces);
        
        if (getPrefix(SOAP_NS) == null) 
            this.namespaces.put("soap", SOAP_NS);
        if (getPrefix(XSD_NS) == null) 
            this.namespaces.put("xsd", XSD_NS);
        if (getPrefix(XSI_NS) == null)
            this.namespaces.put("xsi", XSI_NS);
        if (elements != null) {
            for (int i=0; i<elements.length; i++) {
                parseElement(elements[i]);
            }
        }
    }
    
    public Schema(Map namespaces, Element element) {
        this(namespaces, new Element[] {element});
    }
    
    private void parseNamespaces(Element element) {
        NamedNodeMap attributes = element.getAttributes();
        for (int i=0; i<attributes.getLength(); i++) {
            Attr attr = (Attr) attributes.item(i);
            String name = attr.getName();
            if (name.startsWith("xmlns:")) {
                String prefix = name.substring(6);
                namespaces.put(prefix, attr.getValue());
            } else if (name.equals("xmlns")) {
                namespaces.put("", attr.getValue());
            }
        }
    }
    
    private void parseElement(Element element) {
        if (element == null) return;
        String targetNamespace = element.getAttribute("targetNamespace");
        String prefix = getPrefix(targetNamespace);
        
        NodeList typeNodes = element.getElementsByTagName("complexType");
        for (int j=0; j<typeNodes.getLength(); j++) {
            Node typeNode = typeNodes.item(j);
            String typeName = typeNode.getAttributes().getNamedItem("name").getNodeValue();
            QName typeQName = new QName(targetNamespace, typeName, prefix);
            Type type;
            if (! typeName.startsWith("ArrayOf_")) {
                Field[] fields = parseFields(typeNode);
                type = new Type(typeQName, fields);
            } else {
                QName componentType = parseArray(typeNode);
                type = new Type(typeQName, componentType);
            }
            types.put(typeQName, type);
        }
    }
    
    private Field[] parseFields(Node typeNode) {
        List fields = new LinkedList();
        if (typeNode.getNodeType() == typeNode.ELEMENT_NODE) {
            Element typeElement = (Element) typeNode;
            NodeList elements = ((Element)typeNode).getElementsByTagName("element");
            for (int i=0; i<elements.getLength(); i++) {
                Node element = elements.item(i);
                String fieldName = element.getAttributes().getNamedItem("name").getNodeValue();
                String fieldType = element.getAttributes().getNamedItem("type").getNodeValue();
                // System.err.println("Parsing field " + fieldName + " : " + fieldType);
                int colon = fieldType.indexOf(":");
                QName fieldTypeQName;
                if (colon>-1) {
                    String prefix = fieldType.substring(0, colon);
                    fieldType = fieldType.substring(fieldType.indexOf(":")+1);
                    String namespace = (String) namespaces.get(prefix);
                    fieldTypeQName = new QName(namespace, fieldType);
                } else {
                    fieldTypeQName = new QName(fieldType);
                }
                Field field = new Field(fieldName, fieldTypeQName);
                fields.add(field);
            }
        } else {
            System.err.println("Node Type is " + typeNode.getNodeType());
        }
        if (fields.size()==0) {
            return null;
        } else {
            return (Field[]) fields.toArray(new Field[0]);
        }
    }
    
    private QName parseArray(Node typeNode) {
        if (typeNode.getNodeType() == typeNode.ELEMENT_NODE) {
            Element typeElement = (Element) typeNode;
            NodeList attributeNodes = ((Element)typeNode).getElementsByTagName("attribute");
            for (int i=0; i<attributeNodes.getLength(); i++) {
                Node attributeNode = attributeNodes.item(i);
                NamedNodeMap attributes = attributeNode.getAttributes();
                String arrayType = attributes.getNamedItem("wsdl:arrayType").getNodeValue();
                if (arrayType != null) {
                    int colon = arrayType.indexOf(":");
                    int bracket = arrayType.indexOf("[");
                    String namespaceAbbr = arrayType.substring(0,colon);
                    String namespace = (String) namespaces.get(namespaceAbbr);
                    arrayType = arrayType.substring(colon+1,  bracket);
                    return new QName(namespace, arrayType);
                }
            }
        } else {
            System.err.println("Node Type is " + typeNode.getNodeType());
        }
        return null;
    }
    
    public Type getType(QName typeName) {
        return (Type) types.get(typeName);
    }
    
    public String getPrefix(String namespaceURI) {
        if (namespaceURI == null) 
            throw new NullPointerException("NamespaceURI is NULL");
        Iterator it = namespaces.keySet().iterator();
        while (it.hasNext()) {
            String prefix = (String) it.next();
            String ns = (String) namespaces.get(prefix);
            if (ns != null && namespaceURI.equals(ns)) {
                return prefix;
            }
        }
        int i = 0;
        while (namespaces.get("wsns"+i) != null)
            i++;
        namespaces.put("wsns"+i,  namespaceURI);
        return "wsns"+i;
    }
    
//    public String getQualifiedName(QName qname) {
//        System.err.println("Looking up " + qname);
//        return getPrefix(qname.getNamespaceURI())+":"+qname.getLocalPart();
//    }
}
