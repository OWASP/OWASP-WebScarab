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
 * CharacterSetCalculator.java
 *
 * Created on 17 November 2003, 04:19
 */

package org.owasp.webscarab.plugin.sessionid;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */
public class CustomCalculator implements Calculator {
    
    private Pattern _pattern;
    
    private Map _cache = new HashMap();
    
    Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private String _charset;
    
    /** Creates a new instance of DefaultCalculator */
    public CustomCalculator() {
        this("^(.+)$");
    }
    
    public CustomCalculator(String regex) {
        _pattern = Pattern.compile(regex);
        _charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=";
    }
    
    public boolean add(SessionID id) {
        String value = id.getValue();
        Matcher matcher = _pattern.matcher(value);
        if(matcher.matches() && matcher.groupCount()>=1) {
            value = matcher.group(1);
            return true;
        } else {
            System.err.println("value '" + value + "' did not match the pattern!");
            return false;
        }
    }
    
    public BigInteger calculate(SessionID id) {
        if (_cache.containsKey(id)) return (BigInteger) _cache.get(id);
        String value = id.getValue();
        Matcher matcher = _pattern.matcher(value);
        if(matcher.matches() && matcher.groupCount()>=1) {
            value = matcher.group(1);
        } else {
            return BigInteger.ZERO;
        }
        BigInteger total = BigInteger.ZERO;
        BigInteger max = BigInteger.ONE;
        int length = value.length();
        _logger.fine("Calculating '" + value + "'");
        for (int i=0; i<length; i++) {
            String charset = _charset;
            char ch = value.charAt(length - 1 - i);
            int pos = charset.indexOf(ch);
            _logger.fine("Working on position " + i + ", character '" + ch + "'");
            _logger.fine("pos is " + pos);
            BigInteger val = new BigInteger(Integer.toString(pos));
            total = total.add(val.multiply(max));
            max = max.multiply(new BigInteger(Integer.toString(charset.length())));
        }
        _cache.put(id, total);
        return total;
    }
    
    public void reset() {
        _cache.clear();
    }
    
}
