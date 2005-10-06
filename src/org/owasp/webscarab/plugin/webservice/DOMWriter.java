/*
 * DOMWriter.java
 *
 * Created on 05 October 2005, 04:00
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 *
 * @author rdawes
 */
public class DOMWriter {
    
    private Map namespaces = new HashMap();
    
    /** Creates a new instance of DOMWriter */
    public DOMWriter() {
    }
    
    public void write(Writer writer, Document document) throws IOException {
        BufferedWriter bw = new BufferedWriter(writer);
        bw.write("<?xml version='1.0' encoding='UTF-8'?>\n");
        NodeList children = document.getChildNodes();
        for (int i=0; i<children.getLength(); i++) {
            write(bw, null, children.item(i), 0);
        }
        bw.flush();
        bw.close();
    }
    
    private void write(Writer writer, NSStack nsstack, Node node, int depth) throws IOException {
        nsstack = new NSStack(nsstack);
        if (node.getPrefix() != null) {
            // System.err.println("Prefix for " + node.getNodeName() + " = " + node.getPrefix());
            String nsuri = nsstack.getNamespace(node.getPrefix());
            if (nsuri == null) {
                nsstack.addNamespace(node.getPrefix(), node.getNamespaceURI());
            }
        }
        writer.write(pad(depth));
        writer.write("<"+node.getNodeName());
        NamedNodeMap attrs = node.getAttributes();
        if (attrs != null) {
            writer.write("\n");
            for (int i=0; i<attrs.getLength(); i++) {
                Attr attr = (Attr) attrs.item(i);
                if (attr.getPrefix() != null) {
                    // System.err.println("Prefix for " + attr.getNodeName() + " = " + attr.getPrefix());
                    String nsuri = nsstack.getNamespace(attr.getPrefix());
                    if (nsuri == null) {
                        nsstack.addNamespace(attr.getPrefix(), attr.getNamespaceURI());
                    }
                } else if (attr.getNodeName().startsWith("xmlns:")) {
                    String prefix = attr.getNodeName().substring(6);
                    String nsuri = attr.getNodeValue();
                    // System.err.println("Adding namespace " + prefix + " : " + nsuri);
                    nsstack.addNamespace(prefix, nsuri);
                }
                String value = attr.getValue();
                writer.write(pad(depth+1) + attr.getName() + "='" + value + "'\n");
                if (value != null && value.indexOf(":")>-1 && value.indexOf("://")==-1) {
                    String prefix = value.substring(0, value.indexOf(":"));
                    String nsuri = nsstack.getNamespace(prefix);
                    if (nsuri == null) {
                        System.err.println("WARNING: Use of undeclared namespace prefix : " + prefix);
                    }
                }
            }
            writer.write(pad(depth));
        }
        Map namespaces = nsstack.getNamespaces();
        if (namespaces != null) {
            Iterator nsit = namespaces.keySet().iterator();
            while (nsit.hasNext()) {
                String prefix = (String) nsit.next();
                String nsuri = (String) namespaces.get(prefix);
                Attr attr = (Attr) node.getAttributes().getNamedItem("xmlns:"+prefix);
                if (attr == null) {
                    writer.write(pad(depth+1) + "xmlns:"+prefix+"='"+nsuri+"'\n");
                }
            }
            writer.write(pad(depth));
        }
        writer.write(">");
        NodeList children = node.getChildNodes();
        if (children.getLength() == 1 && children.item(0).getNodeType() == Node.TEXT_NODE) {
            Node text = children.item(0);
            writer.write(text.getNodeValue());
        } else if (children.getLength()>0) {
            writer.write("\n");
            for (int i=0; i<children.getLength(); i++) {
                write(writer, nsstack, children.item(i), depth+1);
            }
            writer.write(pad(depth));
//        } else if (node.getNodeValue() != null) {
//            writer.write(node.getNodeValue());
        }
        writer.write("</"+node.getNodeName()+">\n");
    }
    
    private String pad(int depth) {
        StringBuffer buff = new StringBuffer();
        for (int i=0; i<depth; i++) {
            buff.append("  ");
        }
        return buff.toString();
    }
    
    private class NSStack {
        
        private Map namespaces = null;
        private NSStack parent = null;
        
        public NSStack() {
        }
        
        public NSStack(NSStack parent) {
            this.parent = parent;
        }
        
        public Map getNamespaces() {
            return namespaces;
        }
        
        public void addNamespace(String prefix, String nsuri) {
            if (namespaces == null)
                namespaces = new HashMap();
            namespaces.put(prefix, nsuri);
        }
        
        public String getNamespace(String prefix) {
            if (namespaces != null) {
                String result = (String) namespaces.get(prefix);
                if (result != null) return result;
            }
            if (parent != null)
                return parent.getNamespace(prefix);
            return null;
        }
        
    }
}
