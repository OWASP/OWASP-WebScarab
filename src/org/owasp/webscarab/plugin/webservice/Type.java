/*
 * Type.java
 *
 * Created on 13 September 2005, 04:18
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
public class Type {
    
    private QName name;
    private Field[] fields = null;
    private QName componentName = null;
    
    public Type(QName name) {
        this.name = name;
    }
    
    public Type(QName name, Field[] fields) {
        this(name);
        this.fields = fields;
    }
    
    public Type(QName name, QName componentName) {
        this(name);
        this.componentName = componentName;
    }
    
    public boolean isArray() {
        return componentName != null;
    }
    
    public boolean isComplex() {
        return fields != null;
    }
    
    public QName getTypeQName() {
        return name;
    }
    
    public QName getComponentQName() {
        return componentName;
    }
    
    public Field[] getFields() {
        return fields;
    }
    
    public String toString() {
        StringBuffer buff = new StringBuffer();
        buff.append(name);
        if (fields != null) {
            buff.append(" =>\n");
            for (int i=0; i<fields.length; i++) {
                buff.append("\t").append(fields[i]).append("\n");
            }
        } else if (componentName!= null) {
            buff.append(" =>\n\tArray of ").append(componentName).append("\n");
        } else {
            buff.append("\n");
        }
        return buff.toString();
    }
}
