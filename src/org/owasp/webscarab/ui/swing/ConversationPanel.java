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

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.border.TitledBorder;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

/**
 *
 * @author  rdawes
 */
public class ConversationPanel extends JPanel {
    
    private RequestPanel _requestPanel;
    private ResponsePanel _responsePanel;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private Request _request = null;
    private Response _response = null;
    
    private boolean _requestModified = false;
    private boolean _responseModified = false;
    
    private boolean _requestEditable = false;
    private boolean _responseEditable = false;
    
    private int _selected;
    
    /** Creates new form ConversationPanel */
    public ConversationPanel() {
        _requestPanel = new RequestPanel();
        _responsePanel = new ResponsePanel();
        
        setLayout(new BorderLayout());
        
        JSplitPane splitPane = new JSplitPane();
        splitPane.setOneTouchExpandable(true);
        add(splitPane, BorderLayout.CENTER);

        splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        _requestPanel.setBorder(new TitledBorder("Request"));
        splitPane.setTopComponent(_requestPanel);
        _responsePanel.setBorder(new TitledBorder("Response"));
        splitPane.setBottomComponent(_responsePanel);
        String dividerLocation = Preferences.getPreference("ConversationPanel.dividerLocation");
        if (dividerLocation != null) {
            try {
                splitPane.setDividerLocation(Integer.parseInt(dividerLocation));
            } catch (NumberFormatException nfe) {}
        }
        splitPane.addPropertyChangeListener(new PropertyChangeListener() {
            public void propertyChange(PropertyChangeEvent e) {
                if (e.getPropertyName().equals("dividerLocation")) {
                    Preferences.setPreference("ConversationPanel.dividerLocation", e.getNewValue().toString());
                }
            }
        });
        
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
    
    public static void main(String[] args) {
        final JFrame top = new JFrame("Response Panel");
        top.getContentPane().setLayout(new BorderLayout());
        top.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                System.exit(0);
            }
        });
        final ConversationPanel cp = new ConversationPanel();
        top.getContentPane().add(cp);
        top.setBounds(100,100,800,600);
        top.show();
        if (args.length == 1) {
            top.setTitle(args[0]);
            loadConversation(cp, args[0]);
        }
    }
    
    private static void loadConversation(ConversationPanel cp, String file) {
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
    }
    
}
