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

import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.SiteModelAdapter;
import org.owasp.webscarab.model.SiteModelEvent;

import javax.swing.AbstractListModel;
import javax.swing.SwingUtilities;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class ConversationListModel extends AbstractListModel {
    
    private SiteModel _model = null;
    private Listener _listener = new Listener();
    private int _size = 0;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of ConversationTableModel */
    public ConversationListModel(SiteModel model) {
        _model = model;
        _model.addModelListener(_listener);
        fireContentsChanged(this, 0, getSize());
    }
    
    public Object getElementAt(int index) {
        return _model.getConversationAt(index);
    }
    
    public int getSize() {
        if (_model == null) return 0;
        _size = _model.getConversationCount();
        return _size;
    }
    
    protected void addedConversation(SiteModelEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = _model.getIndexOfConversation(id);
        fireIntervalAdded(this, row, row);
    }
    
    protected void changedConversation(SiteModelEvent evt) {
        ConversationID id = evt.getConversationID();
        int row = _model.getIndexOfConversation(id);
        fireContentsChanged(this, row, row);
    }
    
    protected void removedConversation(SiteModelEvent evt) {
        ConversationID id = evt.getConversationID();
        int position = _model.getIndexOfConversation(id);
        fireIntervalRemoved(this, position, position);
    }
    
    protected void conversationsChanged(SiteModelEvent evt) {
        if (_size>0)
            fireIntervalRemoved(this, 0, _size);
        fireIntervalAdded(this, 0,  getSize());
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(final SiteModelEvent evt) {
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
        
        public void conversationChanged(final SiteModelEvent evt) {
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
                    _logger.warning("Exception! " + e);
                }
            }
        }
        
        public void conversationRemoved(final SiteModelEvent evt) {
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
        
        public void dataChanged(final SiteModelEvent evt) {
            if (SwingUtilities.isEventDispatchThread()) {
                ConversationListModel.this.conversationsChanged(evt);
            } else {
                try {
                    SwingUtilities.invokeAndWait(new Runnable() {
                        public void run() {
                            ConversationListModel.this.conversationsChanged(evt);
                        }
                    });
                } catch (Exception e) {
                    _logger.warning("Exception! " + e);
                }
            }
        }
        
    }
    
}
