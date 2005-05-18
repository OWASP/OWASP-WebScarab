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
 * ConversationRenderer.java
 *
 * Created on 19 October 2004, 09:27
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationModel;

/**
 *
 * @author  rogan
 */
public class ConversationRenderer extends JLabel implements ListCellRenderer {
    
    private ConversationModel _conversationModel;
    
    /** Creates a new instance of ConversationRenderer */
    public ConversationRenderer(ConversationModel conversationModel) {
        _conversationModel = conversationModel;
    }
    
    public java.awt.Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
        //Get the selected index. (The index param isn't
        //always valid, so just use the value.)
        ConversationID id = (ConversationID) value;
        
        if (isSelected) {
            setBackground(list.getSelectionBackground());
            setForeground(list.getSelectionForeground());
        } else {
            setBackground(list.getBackground());
            setForeground(list.getForeground());
        }
        
        if (id == null) {
            setText("");
            return this;
        }
        if (_conversationModel == null) {
            setText(id.toString());
            return this;
        }
        StringBuffer text = new StringBuffer();
        text.append(id).append(" - ");
        text.append(_conversationModel.getRequestMethod(id)).append(" ");
        text.append(_conversationModel.getRequestUrl(id).getSHPP()).append("    ");
        text.append(_conversationModel.getResponseStatus(id));
        setText(text.toString());
        
        return this;
    }
    
}
