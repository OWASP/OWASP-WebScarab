/*
 * HTMLParser.java
 *
 * Created on July 21, 2004, 4:25 PM
 */

package org.owasp.webscarab.parser;

import org.owasp.webscarab.model.Message;
import org.owasp.webscarab.model.HttpUrl;

import org.htmlparser.Parser;
import org.htmlparser.Node;
import org.htmlparser.NodeReader;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.ParserException;

import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;

import java.util.logging.Logger;

/**
 * parses HTML messages
 * @author knoppix
 */
public class HTMLParser implements ContentParser {
    
    private Parser _parser;
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of HTMLParser */
    public HTMLParser() {
        _parser = new Parser();
        _parser.registerScanners();
    }
    
    /**
     * parses the body of the message, and returns a parsed representation
     * See {@link http://htmlparser.sourceforge.net/} for details
     * @param url the url that the message resulted from
     * @param message the Message to parse
     * @return a NodeList containing the various Nodes making up the page
     */
    public Object parseMessage(HttpUrl url, Message message) {
        String contentType = message.getHeader("Content-Type");
        if (contentType == null || !contentType.matches("text/html.*")) {
            return null;
        }
        byte[] content = message.getContent();
        if (content == null || content.length == 0) {
            return null;
        }
        NodeReader reader = new NodeReader(new InputStreamReader(new ByteArrayInputStream(content)), url.toString());
        NodeList nodelist = new NodeList();
        synchronized(_parser) {
            _parser.setReader(reader);
            try {
                Node n;
                for (NodeIterator ni = _parser.elements(); ni.hasMoreNodes(); ) {
                    n = ni.nextNode();
                    nodelist.add(n);
                }
            } catch (ParserException pe) {
                _logger.severe(pe.toString());
            }
        }
        return nodelist;
        
    }
    
}
