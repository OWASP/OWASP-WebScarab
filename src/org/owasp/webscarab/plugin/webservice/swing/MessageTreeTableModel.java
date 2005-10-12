/*
 * MessageTreeTableModel.java
 *
 * Created on 02 October 2005, 10:55
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.plugin.webservice.swing;

import java.util.Iterator;
import java.util.List;
import javax.wsdl.Message;
import javax.wsdl.Part;
import javax.xml.namespace.QName;
import org.owasp.webscarab.plugin.webservice.ArrayValue;
import org.owasp.webscarab.plugin.webservice.ComplexValue;
import org.owasp.webscarab.plugin.webservice.Field;
import org.owasp.webscarab.plugin.webservice.Schema;
import org.owasp.webscarab.plugin.webservice.SimpleValue;
import org.owasp.webscarab.plugin.webservice.Type;
import org.owasp.webscarab.plugin.webservice.Value;
import org.owasp.webscarab.util.swing.treetable.AbstractTreeTableModel;

/**
 *
 * @author rdawes
 */
public class MessageTreeTableModel extends AbstractTreeTableModel {
    
    private static String[] _columnNames = { "Node", "Type", "Nillable", "Value" };
    
    private Schema _schema;
    private Message _message;
    private Part[] _parts;
    private Value[] _values;
    
    public MessageTreeTableModel() {
        _schema = null;
        _message = null;
        _values = null;
        _parts = null;
    }
    
    /** Creates a new instance of MessageTreeTableModel */
    public MessageTreeTableModel(Schema schema, Message message, Value[] values) {
        _schema = schema;
        _message = message;
        List parts = message.getOrderedParts(null);
        _parts = new Part[parts.size()];
        Iterator it = parts.iterator();
        int i=0;
        while (it.hasNext()) {
            _parts[i++] = (Part) it.next();
        }
        _values = values;
    }
    
    public Value[] getValues() {
        return _values;
    }
    
    public Object getChild(Object obj, int param) {
        if (obj == _message) {
            return _parts[param];
        } else if (obj instanceof Part) {
            Part part = (Part) obj;
            Value value = getValueForPart(part);
            ComplexValue cv = (ComplexValue) value;
            return cv.getValue(cv.getFieldName(param));
        } else if (obj instanceof Value) {
            if (obj instanceof ComplexValue) {
                ComplexValue cv = (ComplexValue)obj;
                return cv.getValue(cv.getFieldName(param));
            }
            if (obj instanceof ArrayValue) {
                ArrayValue av = (ArrayValue)obj;
                return av.getValue(param);
            }
        }
        System.err.println("Child " + param + " of " + obj + " was not found!");
        return null;
    }
    
    public int getChildCount(Object obj) {
        if (obj == null) {
            return 0;
        } else if (obj == _message) {
            return _parts.length;
        } else if (obj instanceof Part) {
            Part part = (Part) obj;
            Type type = _schema.getType(part.getTypeName());
            if (type == null) {
                System.err.println("no type for " + part + " : " + part.getTypeName());
                return 0;
            }
            Field[] fields = type.getFields();
            if (fields == null) {
                return 0;
            } else {
                return fields.length;
            }
        } else if (obj instanceof Value) {
            if (obj instanceof SimpleValue) return 0;
            if (obj instanceof ComplexValue) return ((ComplexValue)obj).getFieldCount();
            if (obj instanceof ArrayValue) return ((ArrayValue)obj).getCount();
        }
        return 0;
    }
    
    public int getColumnCount() {
        return _columnNames.length;
    }
    
    public String getColumnName(int column) {
        return _columnNames[column];
    }
    
    public Object getRoot() {
        return _message;
    }
    
    private Value getValueForPart(Part part) {
        for (int i=0; i<_parts.length; i++) {
            if (part == _parts[i]) {
                return _values[i];
            }
        }
        return null;
    }
    
    public Object getValueAt(Object node, int column) {
        if (column == 0) {
            return node;
        } else {
            if (node instanceof Message) {
                return null;
            } else if (node instanceof Part) {
                // System.err.println("Node " + node + " : " + ((Part)node).getTypeName());
                switch (column) {
                    case 1: 
                        QName typeName = ((Part)node).getTypeName();
                        if (typeName != null) {
                            return typeName.getLocalPart();
                        } else {
                            return null;
                        }
                    case 2: return null; // Boolean.FALSE; // FIXME, we should present this info!
                    case 3:
                        if (isLeaf(node)) {
                            SimpleValue value = (SimpleValue) getValueForPart((Part)node);
                            return value.getValue();
                        } else {
                            return null;
                        }
                }
            } else if (node instanceof Value) {
                switch (column) {
                    case 1: return ((Value)node).getTypeName().getLocalPart();
                    case 2: return Boolean.FALSE;
                    case 3:
                        if (isLeaf(node)) {
                            SimpleValue value = (SimpleValue) node;
                            return value.getValue();
                        } else {
                            return null;
                        }
                }
            }
        }
        return null;
    }
    
    public boolean isLeaf(Object obj) {
        if (obj == _message) return false;
        Type type = null;
        if (obj instanceof Part) {
            Part part = (Part) obj;
            try {
                type = _schema.getType(part.getTypeName());
            } catch (NullPointerException npe) {
                System.err.println("_schema = " + _schema + " part = " + part);
            }
        } else if (obj instanceof Value) {
            type = ((Value)obj).getType();
        }
        return type == null;
    }
    
    public void valueForPathChanged(javax.swing.tree.TreePath treePath, Object obj) {
    }
    
    public void setValueAt(Object aValue, Object node, int column) {
        if (isCellEditable(node, column)) {
            if (node instanceof Part) {
                SimpleValue value = (SimpleValue) getValueForPart((Part)node);
                value.setValue(aValue.toString());
            } else if (node instanceof SimpleValue) {
                SimpleValue value = (SimpleValue) node;
                value.setValue(aValue.toString());
            }
        }
    }
    
    public boolean isCellEditable(Object node, int column) {
        return super.isCellEditable(node, column) || (column == 3 && isLeaf(node));
    }
    
}
