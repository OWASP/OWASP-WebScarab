/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
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
import org.htmlparser.NodeFilter;
import org.htmlparser.lexer.Source;
import org.htmlparser.lexer.InputStreamSource;
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
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of HTMLParser */
    public HTMLParser() {
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
        Parser parser = Parser.createParser(new String(content), null);
        try {
            NodeList nodelist = parser.extractAllNodesThatMatch(new NodeFilter() {
		public boolean accept(Node node) {
                    return true;
                }
            });
            return nodelist;
        } catch (ParserException pe) {
            _logger.severe(pe.toString());
            return null;
        }
    }
    
}
