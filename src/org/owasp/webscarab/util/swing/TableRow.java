package org.owasp.webscarab.util.swing;

public interface TableRow {

    Class getColumnClass(int column);
    
    int getColumnCount();
    
    String getColumnName(int column);
    
    Object getValueAt(Object object, int column);
    
    boolean isFieldEditable(Object object, int column);
    
    void setValueAt(Object aValue, Object object, int column);
    
}

