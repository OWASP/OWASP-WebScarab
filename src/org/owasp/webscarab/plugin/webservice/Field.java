/*
 * Field.java
 *
 * Created on 14 September 2005, 10:27
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
public class Field {
    
    private String name;
    private QName type;
    
    /** Creates a new instance of Field */
    public Field(String name, QName type) {
        this.name = name;
        this.type = type;
    }
    
    public String getName() {
        return name;
    }
    
    public QName getType() {
        return type;
    }
    
    public String toString() {
        StringBuffer buff = new StringBuffer();
        buff.append(name).append(" [").append(type).append("]");
        return buff.toString();
    }
}
