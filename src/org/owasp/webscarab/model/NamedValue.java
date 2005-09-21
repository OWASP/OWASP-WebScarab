/*
 * NamedValue.java
 *
 * Created on 19 December 2004, 08:58
 */

package org.owasp.webscarab.model;

import java.util.logging.Logger;
import java.util.logging.Level;

/**
 *
 * @author  rogan
 */
public class NamedValue {
    
    private String _name;
    private String _value;
    
    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.model.NamedValue");
    
    {
        _logger.setLevel(Level.INFO);
    }
    
    /** Creates a new instance of NamedValue */
    public NamedValue(String name, String value) {
        _name = name;
        _value = value;
    }
    
    public String getName() {
        return _name;
    }
    
    public String getValue() {
        return _value;
    }
    
    public String toString() {
        return _name + "='" + _value + "'";
    }
    
    public static NamedValue[] splitNamedValues(String source, String pairSeparator, String nvSeparator) {
        try {
            if (source == null) return new NamedValue[0];
            String[] pairs = source.split(pairSeparator);
            _logger.fine("Split \""+ source + "\" into " + pairs.length);
            NamedValue[] values = new NamedValue[pairs.length];
            for (int i=0; i<pairs.length; i++) {
                String[] nv = pairs[i].split(nvSeparator,2);
                if (nv.length == 2) { 
                    values[i] = new NamedValue(nv[0], nv[1]);
                } else if (nv.length == 1) {
                    values[i] = new NamedValue(nv[0], "");
                } else {
                    values[i] = null;
                }
            }
            return values;
        } catch (ArrayIndexOutOfBoundsException aioob) {
            _logger.warning("Error splitting \"" + source + "\" using '" + pairSeparator + "' and '" + nvSeparator + "'");
        }
        return new NamedValue[0];
    }
    
}
