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
        _requestPanel.setRequest(_request, editable);
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
        _responsePanel.setResponse(response, editable);
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
    
}
