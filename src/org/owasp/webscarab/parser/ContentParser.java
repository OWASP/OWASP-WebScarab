/*
 * ContentParser.java
 *
 * Created on June 24, 2004, 11:42 PM
 */

package org.owasp.webscarab.parser;

import org.owasp.webscarab.model.Message;
import org.owasp.webscarab.model.HttpUrl;

/**
 * The methods required by a class that can parse the content of a message
 * @author knoppix
 */
public interface ContentParser {
    
    
    /**
     * parses the body of the message, and returns a parsed representation
     * @param message the Message to parse
     * @return the parsed representation of the message body
     */    
    Object parseMessage(HttpUrl url, Message message);
    
}
