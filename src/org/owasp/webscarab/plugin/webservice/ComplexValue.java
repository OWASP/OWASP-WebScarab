/*
 * ComplexValue.java
 *
 * Created on 02 October 2005, 07:01
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.util.HashMap;
import java.util.Map;
import javax.xml.namespace.QName;

/**
 *
 * @author rdawes
 */
public class ComplexValue extends Value {
    
    private Map _values = new HashMap();
    
    /** Creates a new instance of ComplexValue */
    public ComplexValue(String name, QName typeName, Type type) {
        super(name, typeName, type);
    }
    
    public int getFieldCount() {
        return getType().getFields().length;
    }
    
    public String getFieldName(int i) {
        return getType().getFields()[i].getName();
    }
    
    public Value getValue(String name) {
        return (Value) _values.get(name);
    }
    
    public void setValue(String name, Value value) {
        _values.put(name, value);
    }
    
}
