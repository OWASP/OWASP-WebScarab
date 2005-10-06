/*
 * Value.java
 *
 * Created on 02 October 2005, 06:53
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
public abstract class Value {
    
    private String _name;
    private QName _typeName;
    private Type _type;
    
    public Value(String name, QName typeName, Type type) {
        _name = name;
        _typeName = typeName;
        _type = type;
    }
    
    public String getName() {
        return _name;
    }
    
    public QName getTypeName() {
        return _typeName;
    }
    
    public Type getType() {
        return _type;
    }
    
}
