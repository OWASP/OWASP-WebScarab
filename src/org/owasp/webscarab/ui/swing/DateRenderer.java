/*
 * DateRenderer.java
 *
 * Created on 08 June 2005, 03:43
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.Preferences;

import java.util.Date;
import javax.swing.JLabel;
import javax.swing.JTable;
import java.awt.Component;
import javax.swing.table.DefaultTableCellRenderer;

import java.text.SimpleDateFormat;

/**
 *
 * @author  rogan
 */
public class DateRenderer extends DefaultTableCellRenderer {
    
    private SimpleDateFormat _sdf;
    
    public DateRenderer() {
        String format = Preferences.getPreference("WebScarab.DateFormat", "yyyy/MM/dd HH:mm:ss");
        _sdf = new SimpleDateFormat(format);
    }
    
    public void setValue(Object value) {
        if ((value != null) && (value instanceof Date)) {
            Date date = (Date) value;
            // value = DateUtil.rfc822Format(date);
            value = _sdf.format(date);
        }
        super.setValue(value);
    }
    
}

