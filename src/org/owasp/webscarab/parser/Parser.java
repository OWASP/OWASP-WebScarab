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
import java.util.logging.Logger;

/**
 * provides an interface for generic parsing of message content. Allows for sharing
 * of parsed content between plugins without performing addional parse steps.
 *
 * Parsed representations should NOT be modified.
 * @author knoppix
 */
public class Parser {
    
    private static List _parsers = new ArrayList();
    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.parser.Parser");
    
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
