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
public class DefaultCalculator implements Calculator {
    
    private Pattern _pattern;
    
    private Map _cache = new HashMap();
    
    Logger _logger = Logger.getLogger(this.getClass().getName());
    
    private ArrayList _chars = new ArrayList();
    
    /** Creates a new instance of DefaultCalculator */
    public DefaultCalculator() {
        this("^(.+)$");
    }
    
    public DefaultCalculator(String regex) {
        _pattern = Pattern.compile(regex);
    }
    
    public boolean add(SessionID id) {
        String value = id.getValue();
        Matcher matcher = _pattern.matcher(value);
        if(matcher.matches() && matcher.groupCount()>=1) {
            value = matcher.group(1);
            return update(value);
        } else {
            System.err.println("value '" + value + "' did not match the pattern!");
            return false;
        }
    }
    
    private boolean update(String value) {
        _logger.fine("Value is '" + value + "'");
        boolean changed = false;
        for (int i=0; i<value.length(); i++) {
            char ch = value.charAt(value.length() - 1 - i);
            _logger.fine("Working on position " + i + ", character '" + ch + "'");
            String set = null;
            if (_chars.size() > i) set = (String) _chars.get(i);
            if (set == null) set = new String();
            _logger.fine("Character set was '" + set + "'");
            String updset = insertCharacter(set, ch);
            if (! updset.equals(set)) {
                _logger.fine("Character set is now '" + updset + "'");
                reset();
                if (_chars.size()>i) { 
                    _chars.set(i, updset);
                } else {
                    _chars.add(i, updset);
                }
                changed = true;
            }
        }
        return changed;
    }
    
    private String insertCharacter(String set, char ch) {
        if (set.indexOf(ch) != -1) return set;
        char[] chars = set.toCharArray();
        int insert = -Arrays.binarySearch(chars, ch) -1;
        StringBuffer buff = new StringBuffer();
        buff.append(chars, 0, insert);
        buff.append(ch);
        buff.append(chars, insert, chars.length - insert);
        return buff.toString();
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
            String charset = (String) _chars.get(i);
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
