/*
 * ComboBoxCellEditor.java
 *
 * Created on 18 June 2005, 10:06
 */

package org.owasp.webscarab.util.swing;

import java.awt.Component;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.ComboBoxModel;
import javax.swing.DefaultCellEditor;
import javax.swing.table.TableCellRenderer;

/**
 *
 * @author  rogan
 */
public class ComboBoxCellEditor extends DefaultCellEditor implements TableCellRenderer {
    
    private ComboBoxModel _model;
    
    /** Creates a new instance of ComboBoxCellEditor */
    public ComboBoxCellEditor(ComboBoxModel model) {
        super(new JComboBox(model));
    }
    
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        JComboBox cb = (JComboBox) getComponent();
        cb.setSelectedItem(value);
        return cb;
    }
        
}
