
package org.owasp.webscarab.util;

import java.util.Stack;
import java.util.List;
import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
import org.w3c.dom.ProcessingInstruction;
import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.ext.LexicalHandler;

public class DOMHandler implements ContentHandler, LexicalHandler {
    
    private Document _document = null;
    private Stack _stack = new Stack();
    private Node _last = null;
    private List _namespaces = null;
    
    public static final String XMLNS_PREFIX = "xmlns";
    public static final String XMLNS_STRING = "xmlns:";
    public static final String XMLNS_URI = "http://www.w3.org/2000/xmlns/";
    
    public DOMHandler() throws ParserConfigurationException {
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        _document = builder.newDocument();
    }
    
    public Document getDocument() {
        return _document;
    }
    
    public void characters(char[] ch, int start, int length) {
        Node last = (Node)_stack.peek();
        
        if (last != _document) {
            final String text = new String(ch, start, length);
            if (_last != null && _last.getNodeType() == Node.TEXT_NODE) {
                ((Text)_last).appendData(text);
            } else{
                _last = last.appendChild(_document.createTextNode(text));
            }
        }
    }
    
    public void startDocument() {
        _stack.push(_document);
    }
    
    public void endDocument() {
        _stack.pop();
    }
    
    public void startElement(String namespace, String localName, String qName, Attributes attrs) {
        Element element = (Element)_document.createElementNS(namespace, qName);
        
        // Add namespace declarations first
        if (_namespaces != null) {
            for (int i = 0; i < _namespaces.size(); i++) {
                String prefix = (String) _namespaces.get(i++);
                
                if (prefix == null || prefix.equals("")) {
                    element.setAttributeNS(XMLNS_URI, XMLNS_PREFIX, (String) _namespaces.get(i));
                }
                else {
                    element.setAttributeNS(XMLNS_URI, XMLNS_STRING + prefix, (String) _namespaces.get(i));
                }
            }
            _namespaces.clear();
        }
        
        // Add attributes to element
        final int nattrs = attrs.getLength();
        for (int i = 0; i < nattrs; i++) {
            if (attrs.getLocalName(i) == null) {
                element.setAttribute(attrs.getQName(i), attrs.getValue(i));
            }
            else {
                element.setAttributeNS(attrs.getURI(i), attrs.getQName(i),
                attrs.getValue(i));
            }
        }
        
        // Append this new node onto current stack node
        Node last = (Node)_stack.peek();
        last.appendChild(element);
        
        // Push this node onto stack
        _stack.push(element);
        _last = null;
    }
    
    public void endElement(String namespace, String localName, String qName) {
        _stack.pop();
        _last = null;
    }
    
    public void startPrefixMapping(String prefix, String uri) {
        if (_namespaces == null) {
            _namespaces = new ArrayList();
        }
        _namespaces.add(prefix);
        _namespaces.add(uri);
    }
    
    public void endPrefixMapping(String prefix) {
        // do nothing
    }
    
    public void ignorableWhitespace(char[] ch, int start, int length) {
        // do nothing
    }
    
    /**
     * adds processing instruction node to DOM.
     */
    public void processingInstruction(String target, String data) {
        Node last = (Node)_stack.peek();
        ProcessingInstruction pi = _document.createProcessingInstruction(target, data);
        if (pi != null){
            last.appendChild(pi);
            _last = pi;
        }
    }
    
    public void setDocumentLocator(Locator locator) {
        // do nothing
    }
    
    public void skippedEntity(String name) {
        // do nothing
    }
    
    
    /**
     * Lexical Handler method to create comment node in DOM tree.
     */
    public void comment(char[] ch, int start, int length) {
        Node last = (Node)_stack.peek();
        Comment comment = _document.createComment(new String(ch,start,length));
        if (comment != null){
            last.appendChild(comment);
            _last = comment;
        }
    }
    
    // Lexical Handler methods- not implemented
    public void startCDATA() { }
    public void endCDATA() { }
    public void startEntity(java.lang.String name) { }
    public void endDTD() { }
    public void endEntity(String name) { }
    public void startDTD(String name, String publicId, String systemId) throws SAXException { }
    
}
