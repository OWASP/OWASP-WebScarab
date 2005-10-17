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
 * ConversationTableModel.java
 *
 * Created on June 21, 2004, 6:05 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.ConversationListener;
import org.owasp.webscarab.model.ConversationEvent;

import javax.swing.AbstractListModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationListModel extends AbstractListModel {
    
    private ConversationModel _model = null;
    private Listener _listener = new Listener();
    private int _size = 0;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationListModel(ConversationModel model) {
        _model = model;
        _model.addConversationListener(_listener);
        fireContentsChanged(this, 0, getSize());
    }
    
    public Object getElementAt(int index) {
        return getConversationAt(index);
    }
    
    public int getIndexOfConversation(ConversationID id) {
        return _model.getIndexOfConversation(id);
    }
    
    public int getConversationCount() {
        return _model.getConversationCount();
    }
    
    public ConversationID getConversationAt(int index) {
        return _model.getConversationAt(index);
    }
    
    public int getSize() {
        if (_model == null) return 0;
        _size = getConversationCount();
        return _size;
    }
    
    protected void addedConversation(ConversationEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = getIndexOfConversation(id);
        if (row>-1) fireIntervalAdded(this, row, row);
    }
    
    protected void changedConversation(ConversationEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = getIndexOfConversation(id);
        if (row>-1) fireContentsChanged(this, row, row);
    }
    
    protected void removedConversation(ConversationEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = getIndexOfConversation(id);
        if (row>-1) fireIntervalRemoved(this, row, row);
    }
    
    protected void conversationsChanged() {
        if (_size>0)
            fireIntervalRemoved(this, 0, _size);
        fireIntervalAdded(this, 0,  getSize());
    }
    
    private class Listener implements ConversationListener {
        
        public void conversationAdded(final ConversationEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                ConversationListModel.this.addedConversation(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            ConversationListModel.this.addedConversation(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception! " + e);
                }
            }
        }
        
        public void conversationChanged(final ConversationEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                ConversationListModel.this.changedConversation(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            ConversationListModel.this.changedConversation(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception! " + e + " : " + e.getStackTrace()[0]);
                }
            }
        }
        
        public void conversationRemoved(final ConversationEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                ConversationListModel.this.removedConversation(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            ConversationListModel.this.removedConversation(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception! " + e);
                }
            }
        }
        
        public void conversationsChanged() {
            if (SwingUtilities.isEventDispatchThread()) {
                ConversationListModel.this.conversationsChanged();
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            ConversationListModel.this.conversationsChanged();
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception! " + e + " : " + e.getStackTrace()[0]);
                    e.printStackTrace();
                }
            }
        }
        
    }
    
}
