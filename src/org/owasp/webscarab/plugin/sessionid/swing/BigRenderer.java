/*
 * BigRenderer.java
 *
 * Created on August 20, 2004, 6:30 PM
 */

package org.owasp.webscarab.plugin.sessionid.swing;

import java.awt.Component;
import javax.swing.Icon;
// import javax.swing.ImageIcon;
import javax.swing.JTable;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;

import java.math.BigInteger;

public class BigRenderer extends DefaultTableCellRenderer {
    Icon bang = null; // new ImageIcon("bang.gif"); // until we actually have a bang.gif
    
    public BigRenderer() {
        setHorizontalAlignment(JLabel.RIGHT);
        setHorizontalTextPosition(SwingConstants.RIGHT);
    }
    
    public Component getTableCellRendererComponent(JTable table,
    Object value, boolean isSelected, boolean hasFocus, int row, int col) {
        // be a little paranoid about where the user tries to use this renderer
        if (value instanceof BigInteger) {
            double dbl = ((BigInteger)value).doubleValue();
            if (dbl == Double.NaN || dbl == Double.POSITIVE_INFINITY || dbl == Double.NEGATIVE_INFINITY) {
                setIcon(bang);
            }
            else {
                setIcon(null);
            }
        }
        else {
            setIcon(bang);
        }
        return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
    }
}
