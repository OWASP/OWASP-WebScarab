/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

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
