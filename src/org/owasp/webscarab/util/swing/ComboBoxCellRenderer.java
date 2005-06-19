/*
 * ComboBoxCellRenderer.java
 *
 * Created on 19 June 2005, 03:46
 */

package org.owasp.webscarab.util.swing;

import java.awt.Component;
import javax.swing.JComboBox;
import javax.swing.ComboBoxModel;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;

/**
 *
 * @author  rogan
 */
public class ComboBoxCellRenderer extends JComboBox implements TableCellRenderer {
    
    /** Creates a new instance of ComboBoxCellRenderer */
    public ComboBoxCellRenderer(ComboBoxModel model) {
        super(model);
    }
    
    public Component getTableCellRendererComponent(JTable table, Object value,
        boolean isSelected, boolean hasFocus, int row, int column) {
        if (isSelected) {
            setForeground(table.getSelectionForeground());
            super.setBackground(table.getSelectionBackground());
        } else {
            setForeground(table.getForeground());
            setBackground(table.getBackground());
        }
        
        // Select the current value
        setSelectedItem(value);
        return this;
    }
    
}