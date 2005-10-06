/*
 * ArrayValue.java
 *
 * Created on 02 October 2005, 07:35
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice;

import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;

/**
 *
 * @author rdawes
 */
public class ArrayValue extends Value {
    
    private Type _componentType;
    private QName _componentTypeName;
    private List _values = new ArrayList();
    
    /** Creates a new instance of ArrayValue */
    public ArrayValue(String name, QName typeName, Type type, QName componentTypeName, Type componentType) {
        super(name, typeName, type);
        _componentTypeName = componentTypeName;
        _componentType = componentType;
    }
    
    public QName getComponentTypeName() {
        return _componentTypeName;
    }
    
    public Type getComponentType() {
        return _componentType;
    }
    
    public int getCount() {
        return _values.size();
    }
    
    public void addValue(Value value) {
        _values.add(value);
    }
    
    public void setValue(int index, Value value) {
        _values.set(index, value);
    }
    
    public void removeValue(int index) {
        _values.remove(index);
    }
    
    public Value getValue(int index) {
        return (Value) _values.get(index);
    }
    
}
