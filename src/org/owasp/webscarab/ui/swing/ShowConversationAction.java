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
 * ShowConversationAction.java
 *
 * Created on August 24, 2004, 11:07 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.ConversationModel;

import javax.swing.JFrame;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;

/**
 *
 * @author  knoppix
 */
public class ShowConversationAction extends AbstractAction {
    
    private ConversationModel _model;
    
    /** Creates a new instance of ShowConversationAction */
    public ShowConversationAction(ConversationModel model) {
        _model = model;
        putValue(NAME, "Show conversation");
        putValue(SHORT_DESCRIPTION, "Opens a new window showing the request and response");
        putValue("CONVERSATION", null);
    }
    
    public void actionPerformed(ActionEvent e) {
        Object o = getValue("CONVERSATION");
        if (o == null || ! (o instanceof ConversationID)) return;
        ConversationID id = (ConversationID) o;
        ConversationPanel cp = new ConversationPanel(_model);
        cp.setSelectedConversation(id);
        JFrame frame = cp.inFrame();
        frame.setVisible(true);
        frame.toFront();
        frame.requestFocus();
    }
    
    public void putValue(String key, Object value) {
        super.putValue(key, value);
        if (key != null && key.equals("CONVERSATION")) {
            if (value != null && value instanceof ConversationID) {
                setEnabled(true);
            } else {
                setEnabled(false);
            }
        }
    }
    
}
