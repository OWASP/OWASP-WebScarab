/*
 * Parser.java
 *
 * Created on September 7, 2004, 10:36 PM
 */

package org.owasp.webscarab.parser;

import org.owasp.webscarab.model.Message;
import org.owasp.webscarab.model.HttpUrl;

import org.owasp.webscarab.util.MRUCache;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;


/**
 * provides an interface for generic parsing of message content. Allows for sharing
 * of parsed content between plugins without performing addional parse steps.
 *
 * Parsed representations should NOT be modified.
 * @author knoppix
 */
public class Parser {
    
    private static List _parsers = new ArrayList();
    
    // we cache the 8 most recent messages and their parsed versions
    private static MRUCache _cache = new MRUCache(8);
    
    static {
        _parsers.add(new HTMLParser());
    }
    
    /** Creates a new instance of Parser */
    private Parser() {
    }
    
    /**
     * returns a parsed representation of the message, requesting
     * the parsers to resolve any links relative to the url provided
     */    
    public static Object parse(HttpUrl url, Message message) {
        if (_cache.containsKey(message)) {
            return _cache.get(message);
        }
        Iterator it = _parsers.iterator();
        Object parsed = null;
        ContentParser parser;
        while(it.hasNext()) {
            parser = (ContentParser) it.next();
            parsed = parser.parseMessage(url, message);
            if (parsed != null) break;
        }
        _cache.put(message, parsed);
        return parsed;
    }
    
}
