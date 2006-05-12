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
 * ConversationPanel2.java
 *
 * Created on 10 June 2005, 12:55
 */

package org.owasp.webscarab.ui.swing;

import java.awt.Event;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.net.MalformedURLException;
import javax.swing.AbstractAction;
import javax.swing.InputMap;
import javax.swing.JSplitPane;
import javax.swing.KeyStroke;
import org.owasp.webscarab.model.ConversationModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Preferences;

import org.owasp.webscarab.util.swing.ListComboBoxModel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Point;

import javax.swing.JFrame;
import javax.swing.border.TitledBorder;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

/**
 * Creates a Swing JPanel that can be used to display a Request and a Response
 * @author rogan
 */
public class ConversationPanel extends javax.swing.JPanel {
    
    private static Dimension _preferredSize = null;
    private static Point _preferredLocation = null;
    
    private ConversationModel _model = null;
    private ConversationID _selected = null;
    
    private JFrame _frame = null;
    private String _title = null;
    private RequestPanel _requestPanel;
    private ResponsePanel _responsePanel;
    
    /** Creates new form ConversationPanel2 */
    public ConversationPanel() {
        initComponents();
        addPanels();
    }
    
    /**
     * Creates new form ConversationPanel2
     * This form displays a tool bar with previous, next and a dropdown selector
     * to allow for stepping through the conversations in the supplied ConversationModel
     * @param model the conversations to step through
     */
    public ConversationPanel(ConversationModel model) {
        _model = model;
        initComponents();
        addPanels();
        ConversationListModel clm = new ConversationListModel(model);
        conversationComboBox.setModel(new ListComboBoxModel(clm));
        conversationComboBox.setRenderer(new ConversationRenderer(model));
        add(toolBar, BorderLayout.NORTH);
        getActionMap().put("TOGGLELAYOUT", new AbstractAction() {
            private static final long serialVersionUID = 1558804946998494321L;
            
            public void actionPerformed(ActionEvent event) {
                if (conversationSplitPane.getOrientation() == JSplitPane.HORIZONTAL_SPLIT) {
                    conversationSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
                } else {
                    conversationSplitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
                }
            }
        });
        InputMap inputMap = getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_T, Event.CTRL_MASK),
                "TOGGLELAYOUT");
    }
    
    private void addPanels() {
        _requestPanel = new RequestPanel();
        // _requestPanel.setBorder(new TitledBorder("Request"));
        conversationSplitPane.setTopComponent(_requestPanel);
        
        _responsePanel = new ResponsePanel();
        // _responsePanel.setBorder(new TitledBorder("Response"));
        conversationSplitPane.setBottomComponent(_responsePanel);
        
        String orientation = Preferences.getPreference("ConversationPanel.orientation");
        if (orientation != null) {
            try {
                conversationSplitPane.setOrientation(Integer.parseInt(orientation));
            } catch (NumberFormatException nfe) {}
        }
        String dividerLocation = Preferences.getPreference("ConversationPanel.dividerLocation");
        if (dividerLocation != null) {
            try {
                conversationSplitPane.setDividerLocation(Integer.parseInt(dividerLocation));
            } catch (NumberFormatException nfe) {}
        }
        conversationSplitPane.addPropertyChangeListener(new PropertyChangeListener() {
            public void propertyChange(PropertyChangeEvent e) {
                if (e.getPropertyName().equals(JSplitPane.DIVIDER_LOCATION_PROPERTY)) {
                    Preferences.setPreference("ConversationPanel.dividerLocation", e.getNewValue().toString());
                } else if (e.getPropertyName().equals(JSplitPane.ORIENTATION_PROPERTY)) {
                    Preferences.setPreference("ConversationPanel.orientation", e.getNewValue().toString());
                }
            }
        });
    }
    
    private void resizeFrame() {
        if (_preferredSize == null) {
            try {
                int width = Integer.parseInt(Preferences.getPreference("ConversationFrame.width","600"));
                int height = Integer.parseInt(Preferences.getPreference("ConversationFrame.height","500"));
                _preferredSize = new Dimension(width, height);
            } catch (Exception e) {
                _preferredSize = new Dimension(800, 600);
            }
        }
        if (_preferredLocation == null) {
            try {
                String value = Preferences.getPreference("ConversationFrame.x");
                if (value != null) {
                    int x = Integer.parseInt(value);
                    value = Preferences.getPreference("ConversationFrame.y");
                    int y = Integer.parseInt(value);
                    _preferredLocation = new Point(x,y);
                }
            } catch (Exception e) {
            }
        }
        if (_preferredLocation != null) _frame.setLocation(_preferredLocation);
        if (_preferredSize != null) _frame.setSize(_preferredSize);
        
        _frame.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentMoved(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredLocation = _frame.getLocation();
                Preferences.setPreference("ConversationFrame.x", Integer.toString(_preferredLocation.x));
                Preferences.setPreference("ConversationFrame.y", Integer.toString(_preferredLocation.y));
            }
            public void componentResized(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredSize = _frame.getSize();
                Preferences.setPreference("ConversationFrame.width", Integer.toString(_preferredSize.width));
                Preferences.setPreference("ConversationFrame.height", Integer.toString(_preferredSize.height));
            }
        });
    }
    
    /**
     * Sets the request to display.
     * @param request The request to display (can be null)
     * @param editable whether the request should be editable or not
     */
    public void setRequest(Request request, boolean editable) {
        _requestPanel.setEditable(editable);
        _requestPanel.setRequest(request);
    }
    
    /**
     * indicates whether the request has been modified
     * @return true if the request has been modified, false otherwise
     */
    public boolean isRequestModified() {
        return _requestPanel.isModified();
    }
    
    /**
     * returns the request currently displayed
     * @return the request currently displayed
     */
    public Request getRequest() throws MalformedURLException {
        return _requestPanel.getRequest();
    }
    
    public void setResponse(Response response, boolean editable) {
        _responsePanel.setEditable(editable);
        _responsePanel.setResponse(response);
    }
    
    public boolean isResponseModified() {
        return _responsePanel.isModified();
    }
    
    public Response getResponse() {
        return _responsePanel.getResponse();
    }
    
    /**
     * Sets the conversation to be displayed in the form.
     * This only makes sense if the ConversationModel constructor was used!
     * @param id the conversation to display
     */
    public void setSelectedConversation(ConversationID id) {
        _selected = id;
        conversationComboBox.setSelectedItem(_selected);
    }
    
    public ConversationID getSelectedConversation() {
        return _selected;
    }
    
    /**
     * constructs a JFrame around the ConversationPanel
     * @return the frame
     */
    public JFrame inFrame() {
        ConversationID selected = getSelectedConversation();
        if (selected != null) {
            return inFrame("WebScarab - conversation " + selected);
        }
        return inFrame(null);
    }
    
    /**
     * constructs a JFrame around the ConversationPanel
     * @param title the title of the Frame
     * @return the frame
     */
    public JFrame inFrame(String title) {
        _title = title;
        _frame = new JFrame();
        _frame.getContentPane().add(this);
        _frame.setTitle(_title);
        resizeFrame();
        return _frame;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        toolBar = new javax.swing.JToolBar();
        previousButton = new javax.swing.JButton();
        nextButton = new javax.swing.JButton();
        conversationComboBox = new javax.swing.JComboBox();
        conversationSplitPane = new javax.swing.JSplitPane();

        toolBar.setFloatable(false);
        previousButton.setMnemonic('P');
        previousButton.setText("Previous");
        previousButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                previousButtonActionPerformed(evt);
            }
        });

        toolBar.add(previousButton);

        nextButton.setMnemonic('N');
        nextButton.setText("Next");
        nextButton.setMaximumSize(new java.awt.Dimension(65, 27));
        nextButton.setMinimumSize(new java.awt.Dimension(65, 27));
        nextButton.setPreferredSize(new java.awt.Dimension(65, 27));
        nextButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextButtonActionPerformed(evt);
            }
        });

        toolBar.add(nextButton);

        conversationComboBox.setMaximumSize(new java.awt.Dimension(600, 32767));
        conversationComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                conversationComboBoxActionPerformed(evt);
            }
        });

        toolBar.add(conversationComboBox);

        setLayout(new java.awt.BorderLayout());

        conversationSplitPane.setDividerLocation(100);
        conversationSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        conversationSplitPane.setResizeWeight(0.3);
        conversationSplitPane.setOneTouchExpandable(true);
        add(conversationSplitPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    private void conversationComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_conversationComboBoxActionPerformed
        ConversationID id = (ConversationID) conversationComboBox.getSelectedItem();
        if (id == null) {
            setRequest(null, false);
            setResponse(null, false);
            if (_frame != null)
                _frame.setTitle("WebScarab - no conversation selected");
        } else {
            Request request = _model.getRequest(id);
            Response response = _model.getResponse(id);
            setRequest(request, false);
            setResponse(response, false);
            if (_frame != null)
                _frame.setTitle("WebScarab - conversation " + id);
        }
    }//GEN-LAST:event_conversationComboBoxActionPerformed
    
    private void nextButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextButtonActionPerformed
        int index = conversationComboBox.getSelectedIndex();
        if (index+1<conversationComboBox.getModel().getSize())
            conversationComboBox.setSelectedIndex(index+1);
    }//GEN-LAST:event_nextButtonActionPerformed
    
    private void previousButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_previousButtonActionPerformed
        int index = conversationComboBox.getSelectedIndex();
        if (index>0)
            conversationComboBox.setSelectedIndex(index-1);
    }//GEN-LAST:event_previousButtonActionPerformed
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        try {
            final org.owasp.webscarab.model.FrameworkModel model = new org.owasp.webscarab.model.FrameworkModel();
            model.setSession("FileSystem",new java.io.File("/tmp/l/1"),"");
            ConversationPanel cp = new ConversationPanel(model.getConversationModel());
            JFrame frame = cp.inFrame();
            frame.addWindowListener(new java.awt.event.WindowAdapter() {
                public void windowClosing(java.awt.event.WindowEvent evt) {
                    System.exit(0);
                }
            });
            
            frame.setVisible(true);
            cp.setSelectedConversation(new ConversationID(1));
        } catch (org.owasp.webscarab.model.StoreException se) {
            se.printStackTrace();
            System.exit(0);
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox conversationComboBox;
    private javax.swing.JSplitPane conversationSplitPane;
    private javax.swing.JButton nextButton;
    private javax.swing.JButton previousButton;
    private javax.swing.JToolBar toolBar;
    // End of variables declaration//GEN-END:variables
    
}
