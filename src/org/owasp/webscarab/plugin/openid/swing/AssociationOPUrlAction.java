/***********************************************************************
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2011 FedICT
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
 */

package org.owasp.webscarab.plugin.openid.swing;

import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.JTextField;

/**
 *
 * @author Frank Cornelis
 */
public class AssociationOPUrlAction extends AbstractAction {

    private final JTextField opUrlTextField;
    
    public AssociationOPUrlAction(JTextField opUrlTextField) {
        this.opUrlTextField = opUrlTextField;
        putValue(NAME, "Use as OP URL for association establishment");
    }
    
    @Override
    public void actionPerformed(ActionEvent e) {
        String opUrl = (String) getValue("OP-URL");
        this.opUrlTextField.setText(opUrl);
    }
    
    @Override
    public void putValue(String key, Object value) {
        super.putValue(key, value);
        if (null == key) {
            return;
        }
        if (false == "OP-URL".equals(key)) {
            return;
        }
        if (null == value) {
            setEnabled(false);
        } else {
            setEnabled(true);
        }
    }
}
