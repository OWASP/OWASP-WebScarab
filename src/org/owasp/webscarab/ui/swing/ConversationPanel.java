/*
 * ConversationPanel.java
 *
 * Created on November 7, 2003, 10:56 AM
 */

package org.owasp.webscarab.ui.swing;

import javax.swing.JFrame;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.Toolkit;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import bsh.Interpreter;
import bsh.EvalError;
import bsh.util.JConsole;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */
public class ConversationPanel extends javax.swing.JPanel {
    
    private RequestPanel _requestPanel;
    private ResponsePanel _responsePanel;
    private JFrame _frame = null;
    
    private Thread _thread;
    private Interpreter _interpreter;
    private JConsole _console;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private Request _request = null;
    private Response _response = null;
    
    private boolean _requestModified = false;
    private boolean _responseModified = false;
    
    private boolean _requestEditable = false;
    private boolean _responseEditable = false;
    
    private int _selected;
    
    private static Dimension _preferredSize = new Dimension(600,500);
    private static Point _preferredLocation = null;
    
    /** Creates new form ConversationPanel */
    public ConversationPanel() {
        initComponents();
        
        _requestPanel = new RequestPanel();
        _responsePanel = new ResponsePanel();
        
        _console = new JConsole();
        _interpreter = new Interpreter(_console);
        _interpreter.setExitOnEOF(false);
        _thread = new Thread(_interpreter, "BeanShell interpreter");
        _thread.setDaemon(true);
        _thread.start();
        
        tabbedPane.insertTab("Request", null, _requestPanel, null, 0);
        tabbedPane.insertTab("Response", null, _responsePanel, null, 1);
        tabbedPane.insertTab("Script", null, _console, null, 2);
        
        _selected = tabbedPane.getSelectedIndex();
        
        tabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                if (_selected == 0 && _requestPanel.isModified()) {
                    _request = _requestPanel.getRequest();
                    _requestModified = true;
                } else if (_selected == 1 && _responsePanel.isModified()) {
                    _response = _responsePanel.getResponse();
                    _responseModified = true;
                } else if (_selected == 2) {
                    try {
                        if (_requestEditable) {
                            _request = (Request) _interpreter.get("request");
                            _requestModified = true;
                        }
                        if (_responseEditable) {
                            _response = (Response) _interpreter.get("response");
                            _responseModified = true;
                        }
                    } catch (EvalError ee) {
                        _logger.warning("Error getting request and response from the interpreter: " + ee);
                    }
                }
                
                _selected = tabbedPane.getSelectedIndex();
                
                if (_selected == 0) {
                    if (_requestModified) _requestPanel.setRequest(_request, _requestEditable);
                } else if (_selected == 1) {
                    if (_responseModified) _responsePanel.setResponse(_response, _responseEditable);
                } else if (_selected == 2) {
                    try {
                        _interpreter.set("request", _requestPanel.getRequest());
                        _requestModified = true;
                        _interpreter.set("response", _responsePanel.getResponse());
                        _responseModified = true;
                    } catch (EvalError ee) {
                        _logger.warning("Error setting request and response: " + ee);
                    }
                }
            }
        });
        
    }
    
    public void setRequest(Request request, boolean editable) {
        if (request != null) request = new Request(request);
        _request = request;
        _requestEditable = editable;
        _requestModified = false;
        _requestPanel.setRequest(_request, editable);
        try {
            _interpreter.set("request", _request);
        } catch (EvalError ee) {
            _logger.warning("Error setting request: " + ee);
        }
    }
    
    public boolean isRequestModified() {
        return _requestModified || _requestPanel.isModified();
    }
    
    public Request getRequest() {
        if (_requestEditable) {
            if (tabbedPane.getTitleAt(_selected).equals("Request") && _requestPanel.isModified()) {
                _request = _requestPanel.getRequest();
            } else if (tabbedPane.getTitleAt(_selected).equals("Script")) {
                try {
                    _request = (Request) _interpreter.get("request");
                    _requestModified = true;
                } catch (EvalError ee) {
                    _logger.warning("Error getting request from the interpreter: " + ee);
                }
            }
        }
        return _request;
    }
    
    public void setResponse(Response response, boolean editable) {
        _response = response;
        _responseEditable = editable;
        _responseModified = false;
        _responsePanel.setResponse(response, editable);
        try {
            _interpreter.set("response", response);
        } catch (EvalError ee) {
            _logger.warning("Error setting response: " + ee);
        }
    }
    
    public boolean isResponseModified() {
        return _responseModified || _responsePanel.isModified();
    }
    
    public Response getResponse() {
        if (_responseEditable) {
            if (tabbedPane.getTitleAt(_selected).equals("Response") && _responsePanel.isModified()) {
                _response = _responsePanel.getResponse();
            } else if (tabbedPane.getTitleAt(_selected).equals("Script")) {
                try {
                    _response = (Response) _interpreter.get("response");
                    _responseModified = true;
                } catch (EvalError ee) {
                    _logger.warning("Error getting response from the interpreter: " + ee);
                }
            }
        }
        return _response;
    }
    
    public JFrame inFrame() {
        return inFrame("Conversation Panel");
    }
    
    public void stopInterpreter() {
        // FIXME TODO Something needs to be done here to stop the JConsole too.
        // It is waiting on a JConsole$BlockingPipedInputStream
        _thread.interrupt();
    }
    
    public JFrame inFrame(String title) {
        if (_frame != null) {
            return _frame;
        }
        _frame = new JFrame(title);
        _frame.getContentPane().setLayout(new java.awt.BorderLayout());
        _frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                stopInterpreter();
            }
        });
        _frame.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentMoved(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredLocation = _frame.getLocation();
            }
            public void componentResized(java.awt.event.ComponentEvent evt) {
                if (!_frame.isVisible()) return;
                _preferredSize = _frame.getSize();
            }
        });
        _frame.getContentPane().add(this);
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
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        tabbedPane = new javax.swing.JTabbedPane();

        setLayout(new java.awt.BorderLayout());

        add(tabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTabbedPane tabbedPane;
    // End of variables declaration//GEN-END:variables
    
}
