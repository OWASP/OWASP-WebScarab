/*
 * SimpleValue.java
 *
 * Created on 02 October 2005, 06:56
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import javax.xml.namespace.QName;

/**
 *
 * @author rdawes
 */
public class SimpleValue extends Value {
    
    private Object _value = null;
    
    /** Creates a new instance of SimpleValue */
    public SimpleValue(String name, QName typeName, Type type) {
        super(name, typeName, type);
    }
    
    public Object getValue() {
        return _value;
    }

    public void setValue(Object value) {
        _value = value;
    }
    
}
