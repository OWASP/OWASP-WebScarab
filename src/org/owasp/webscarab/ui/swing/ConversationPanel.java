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
 * ConversationPanel.java
 *
 * Created on November 7, 2003, 10:56 AM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.JSplitPane;
import javax.swing.border.TitledBorder;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.awt.Dimension;
import java.awt.Point;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

import java.util.logging.Logger;

import javax.swing.JButton;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.IOException;

/**
 *
 * @author  rdawes
 */
public class ConversationPanel extends javax.swing.JPanel {
    
    private RequestPanel _requestPanel;
    private ResponsePanel _responsePanel;
    private JFrame _frame = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private Request _request = null;
    private Response _response = null;
    
    private boolean _requestModified = false;
    private boolean _responseModified = false;
    
    private boolean _requestEditable = false;
    private boolean _responseEditable = false;
    
    private int _selected;
    
    private static Dimension _preferredSize = null;
    private static Point _preferredLocation = null;
    
    /** Creates new form ConversationPanel */
    public ConversationPanel() {
        _requestPanel = new RequestPanel();
        _responsePanel = new ResponsePanel();
        
        setLayout(new java.awt.BorderLayout());
        
        if (false) {
            JTabbedPane tabbedPane = new javax.swing.JTabbedPane();
            add(tabbedPane, java.awt.BorderLayout.CENTER);
            
            tabbedPane.insertTab("Request", null, _requestPanel, null, 0);
            tabbedPane.insertTab("Response", null, _responsePanel, null, 1);
            tabbedPane.addChangeListener(new ChangeListener() {
                public void stateChanged(ChangeEvent e) {
                    // _logger.info("State Changed : " + e);
                }
            });
        } else {
            JSplitPane splitPane = new JSplitPane();
            splitPane.setOneTouchExpandable(true);
            add(splitPane, java.awt.BorderLayout.CENTER);
            
            splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
            _requestPanel.setBorder(new TitledBorder("Request"));
            splitPane.setTopComponent(_requestPanel);
            _responsePanel.setBorder(new TitledBorder("Response"));
            splitPane.setBottomComponent(_responsePanel);
            splitPane.addPropertyChangeListener(new PropertyChangeListener() {
                public void propertyChange(PropertyChangeEvent e) {
                    // _logger.info("Property Changed : " + e);
                }
            });
        }
        
        
    }
    
    public void setRequest(Request request, boolean editable) {
        if (request != null) request = new Request(request);
        _request = request;
        _requestEditable = editable;
        _requestModified = false;
        _requestPanel.setEditable(editable);
        _requestPanel.setRequest(_request);
    }
    
    public boolean isRequestModified() {
        return _requestModified || _requestPanel.isModified();
    }
    
    public Request getRequest() {
        if (_requestEditable) {
            if (_requestPanel.isModified()) {
                _request = _requestPanel.getRequest();
            }
        }
        return _request;
    }
    
    public void setResponse(Response response, boolean editable) {
        _response = response;
        _responseEditable = editable;
        _responseModified = false;
        _responsePanel.setEditable(editable);
        _responsePanel.setResponse(response);
    }
    
    public boolean isResponseModified() {
        return _responseModified || _responsePanel.isModified();
    }
    
    public Response getResponse() {
        if (_responseEditable) {
            if (_responsePanel.isModified()) {
                _response = _responsePanel.getResponse();
            }
        }
        return _response;
    }
    
    public JFrame inFrame() {
        return inFrame("Conversation Panel");
    }
    
    public JFrame inFrame(String title) {
        if (_frame != null) {
            return _frame;
        }
        _frame = new JFrame(title);
        _frame.getContentPane().setLayout(new java.awt.BorderLayout());
        _frame.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentMoved(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredLocation = _frame.getLocation();
                Preferences.setPreference("ConversationPanel.x", Integer.toString(_preferredLocation.x));
                Preferences.setPreference("ConversationPanel.y", Integer.toString(_preferredLocation.y));
            }
            public void componentResized(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredSize = _frame.getSize();
                Preferences.setPreference("ConversationPanel.width", Integer.toString(_preferredSize.width));
                Preferences.setPreference("ConversationPanel.height", Integer.toString(_preferredSize.height));
            }
        });
        _frame.getContentPane().add(this);
        if (_preferredSize == null) {
            try {
                int width = Integer.parseInt(Preferences.getPreference("ConversationPanel.width","600"));
                int height = Integer.parseInt(Preferences.getPreference("ConversationPanel.height","500"));
                _preferredSize = new Dimension(width, height);
            } catch (NumberFormatException nfe) {
                _logger.warning("Error parsing ConversationPanel dimensions: " + nfe);
            } catch (NullPointerException npe) {
            }
        }
        if (_preferredLocation == null) {
            try {
                String value = Preferences.getPreference("ConversationPanel.x");
                if (value != null) {
                    int x = Integer.parseInt(value);
                    value = Preferences.getPreference("ConversationPanel.y");
                    int y = Integer.parseInt(value);
                    _preferredLocation = new Point(x,y);
                }
            } catch (NumberFormatException nfe) {
                _logger.warning("Error parsing ConversationPanel location: " + nfe);
            } catch (NullPointerException npe) {
            }
        }
        if (_preferredLocation != null) _frame.setLocation(_preferredLocation);
        if (_preferredSize != null) {
            _frame.setSize(_preferredSize);
        } else {
            _frame.pack();
        }
        return _frame;
    }
    
    public JFrame getFrame() {
        return _frame;
    }
    
    public static void main(String[] args) {
        final JFrame top = new JFrame("Response Panel");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        final ConversationPanel cp = new ConversationPanel();
        top.getContentPane().add(cp);
        top.setBounds(100,100,800,600);
        top.show();
        if (args.length == 0) {
            JButton button = new JButton("NEXT");
            final BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
            button.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    loadConversation(top, cp, br);
                }
            });
            loadConversation(top, cp, br);
        } else if (args.length == 1) {
            loadConversation(top, cp, args[0]);
        }
    }
    
    private static void loadConversation(JFrame top, ConversationPanel cp, String file) {
        Request request = new Request();
        Response response = new Response();
        try {
            FileInputStream fis = new FileInputStream(file+"-request");
            request.read(fis);
            request.flushContentStream();
            fis.close();
            fis = new FileInputStream(file+"-response");
            response.read(fis);
            response.flushContentStream();
            fis.close();
        } catch (IOException ioe) {
            System.err.println(file + ": IOException: " + ioe.getMessage());
        }
        cp.setRequest(request, false);
        cp.setResponse(response, false);
        top.setTitle(file);
    }
    
    private static void loadConversation(JFrame top, ConversationPanel cp, BufferedReader br) {
        try {
            String file = br.readLine();
            if (file == null) {
                System.exit(0);
            }
            loadConversation(top, cp, file);
        } catch (IOException ioe) {
            System.err.println("IOException: " + ioe.getMessage());
        }
    }
    
}
