/*
 * RequestPanel.java
 *
 * Created on 02 June 2003, 02:24
 */

package org.owasp.webscarab.ui.swing;

import java.net.URL;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.JComboBox;
import javax.swing.DefaultCellEditor;

import java.io.ByteArrayInputStream;
import java.util.Vector;

import org.owasp.util.URLUtil;
import org.owasp.webscarab.model.Request;

/**
 *
 * @author  rdawes
 */
public class RequestPanel extends javax.swing.JPanel {
    
    private boolean[] _validPanel;
    private boolean _editable = false;
    private Request _request;
    
    /** Creates new form RequestPanel */
    public RequestPanel() {
        this(null);
    }
    
    public RequestPanel(Request request) {
        this(request, false);
    }
    
    public RequestPanel(Request request, boolean editable) {
        initComponents();
        
        JComboBox comboBox = new JComboBox(new String[] {"FRAGMENT","QUERY","COOKIE","BODY"});
        parameterTable.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(comboBox));
        
        setEditable(editable);
        setRequest(request);
        displayTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                int currentPanel = displayTabbedPane.getSelectedIndex();
                if (currentPanel == 0) {
                    updateRequest(1);
                } else if (currentPanel == 1) {
                    updateRequest(0);
                }
                updateFields(currentPanel);
            }
        });
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
        rawTextArea.setEditable(editable);
        methodTextField.setEditable(editable);
        pathTextField.setEditable(editable);
        ((ParameterTableModel)parameterTable.getModel()).setEditable(editable);
        if (editable) {
            parameterTable.setBackground(new java.awt.Color(255, 255, 255));
        } else {
            parameterTable.setBackground(new java.awt.Color(204, 204, 204));
        }
        editPanel.setVisible(editable);
    }
    
    public void setRequest(Request request) {
        if (request != null) {
            _request = new Request(request);
        } else {
            _request = null;
        }
        _validPanel = new boolean[] {false, false};
        updateFields(displayTabbedPane.getSelectedIndex());
    }
    
    public Request getRequest() {
        int panel = displayTabbedPane.getSelectedIndex();
        updateRequest(panel);
        return _request;
    }
    
    private void updateFields(int panel) {
        // we have already populated the fields in this panel, and they have not been changed
		if (_validPanel[panel]) return; 
        if (_request != null) {
            if (panel == 0) {
                rawTextArea.setText(_request.toString("\n"));
                rawTextArea.setCaretPosition(0);
            } else if (panel == 1) {
                methodTextField.setText(_request.getMethod());
                URL url = _request.getURL();
                pathTextField.setText(URLUtil.schemeAuth(url)+url.getPath());
                ((ParameterTableModel)parameterTable.getModel()).setParameters(_request.getParameters());
                if (!_editable && parameterTable.getModel().getRowCount() == 0) {
                    parameterPanel.setVisible(false);
                } else {
                    parameterPanel.setVisible(true);
                }
            }
        } else {
            if (panel == 0) {
                rawTextArea.setText("");
            } else if (panel == 1) {
                methodTextField.setText("");
                pathTextField.setText("");
                ((ParameterTableModel)parameterTable.getModel()).clear();
            }
        }
        _validPanel[panel] = true;
    }
    
    private void updateRequest(int panel) {
        if (_editable && panel == 0) {
            // we must parse the rawTextArea
            try {
                _validPanel[panel] = false;
                _request = new Request();
                _request.read(new ByteArrayInputStream(rawTextArea.getText().getBytes()));
                String cl = _request.getHeader("Content-Length");
                if (cl != null) {
                    byte[] content = _request.getContent(); // read the content
                    if (content == null) {
                        _request.setHeader("Content-Length","0"); // update the header
                    } else {
                        _request.setHeader("Content-Length", Integer.toString(content.length));
                    }
                }
            } catch (Exception e) {
                System.err.println("Error trying to parse the text area : " + e);
                _request = null;
                return;
            }
        } else if (_editable && panel == 1) {
            // we must update based on the tables
            try {
                _validPanel[panel] = false;
                if (_request == null) {
					_request = new Request();
                }
                _request.setMethod(methodTextField.getText());
                _request.setURL(pathTextField.getText());
                ParameterTableModel ptm = (ParameterTableModel)parameterTable.getModel();
                String[][] params = ptm.getParameters();
                _request.setParameters(params);
				byte[] content = _request.getContent();
				if (content != null) {
					_request.setHeader("Content-Length",Integer.toString(content.length));
				}
            } catch (Exception e) {
                System.err.println("Error trying to parse the tabular view : " + e);
                _request = null;
				return;
            }
        }
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        displayTabbedPane = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        rawTextArea = new javax.swing.JTextArea();
        jPanel2 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        methodTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        pathTextField = new javax.swing.JTextField();
        parameterPanel = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        parameterTable = new javax.swing.JTable();
        editPanel = new javax.swing.JPanel();
        addParameterButton = new javax.swing.JButton();
        deleteParameterButton = new javax.swing.JButton();

        setLayout(new java.awt.GridBagLayout());

        jPanel1.setLayout(new java.awt.GridBagLayout());

        jScrollPane1.setMinimumSize(null);
        rawTextArea.setBackground((java.awt.Color) javax.swing.UIManager.getDefaults().get("TextField.inactiveBackground"));
        rawTextArea.setEditable(false);
        jScrollPane1.setViewportView(rawTextArea);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel1.add(jScrollPane1, gridBagConstraints);

        displayTabbedPane.addTab("Raw", jPanel1);

        jPanel2.setLayout(new java.awt.GridBagLayout());

        jLabel1.setLabelFor(methodTextField);
        jLabel1.setText("Method");
        jLabel1.setMinimumSize(new java.awt.Dimension(60, 20));
        jLabel1.setPreferredSize(new java.awt.Dimension(60, 20));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(jLabel1, gridBagConstraints);

        methodTextField.setBackground((java.awt.Color) javax.swing.UIManager.getDefaults().get("TextField.inactiveBackground"));
        methodTextField.setMinimumSize(new java.awt.Dimension(60, 20));
        methodTextField.setPreferredSize(new java.awt.Dimension(60, 20));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(methodTextField, gridBagConstraints);

        jLabel2.setLabelFor(pathTextField);
        jLabel2.setText("Path");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(jLabel2, gridBagConstraints);

        pathTextField.setBackground((java.awt.Color) javax.swing.UIManager.getDefaults().get("TextField.inactiveBackground"));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        jPanel2.add(pathTextField, gridBagConstraints);

        parameterPanel.setLayout(new java.awt.GridBagLayout());

        jLabel4.setLabelFor(parameterTable);
        jLabel4.setText("Parameters");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        parameterPanel.add(jLabel4, gridBagConstraints);

        jScrollPane2.setMinimumSize(null);
        parameterTable.setBackground(new java.awt.Color(204, 204, 204));
        parameterTable.setModel(new ParameterTableModel());
        jScrollPane2.setViewportView(parameterTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        parameterPanel.add(jScrollPane2, gridBagConstraints);

        editPanel.setLayout(new java.awt.GridBagLayout());

        addParameterButton.setText("Add");
        addParameterButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addParameterButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.SOUTH;
        gridBagConstraints.weighty = 1.0;
        editPanel.add(addParameterButton, gridBagConstraints);

        deleteParameterButton.setText("Delete");
        deleteParameterButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteParameterButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.NORTH;
        gridBagConstraints.weighty = 1.0;
        editPanel.add(deleteParameterButton, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.weighty = 1.0;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        parameterPanel.add(editPanel, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.gridheight = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        jPanel2.add(parameterPanel, gridBagConstraints);

        displayTabbedPane.addTab("Tabular", jPanel2);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(displayTabbedPane, gridBagConstraints);

    }//GEN-END:initComponents
    
    private void deleteParameterButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteParameterButtonActionPerformed
        ParameterTableModel ptm = (ParameterTableModel)parameterTable.getModel();
        int selected = parameterTable.getSelectedRow();
        if (selected >= 0) {
            ptm.deleteRow(selected);
        }
    }//GEN-LAST:event_deleteParameterButtonActionPerformed
    
    private void addParameterButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addParameterButtonActionPerformed
        ParameterTableModel ptm = (ParameterTableModel)parameterTable.getModel();
        int selected = parameterTable.getSelectedRow();
        if (selected < 0) {
            ptm.insertRow(0);
        } else {
            ptm.insertRow(selected+1);
        }
    }//GEN-LAST:event_addParameterButtonActionPerformed
    
    public static void main(String[] args) {
        javax.swing.JFrame top = new javax.swing.JFrame("Request Panel");
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        
        RequestPanel rp = new RequestPanel();
        rp.setEditable(false);
        top.getContentPane().add(rp);
        top.setBounds(100,100,600,400);
        try {
            Request request = new Request();
            request.setMethod("GET");
            //            request.setURL("http://localhost:8080/index.html?param=1");
            request.setURL("http://localhost:8080/index.html");
            request.setVersion("HTTP/1.0");
            //            request.setHeader("Cookie","name=value");
            rp.setRequest(request);
            top.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addParameterButton;
    private javax.swing.JButton deleteParameterButton;
    private javax.swing.JTabbedPane displayTabbedPane;
    private javax.swing.JPanel editPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextField methodTextField;
    private javax.swing.JPanel parameterPanel;
    private javax.swing.JTable parameterTable;
    private javax.swing.JTextField pathTextField;
    private javax.swing.JTextArea rawTextArea;
    // End of variables declaration//GEN-END:variables
    
    private class ParameterTableModel extends javax.swing.table.AbstractTableModel {
        
        protected String [] _columnNames = {
            "Location", "Name", "Value"
        };
        
        protected Vector _data = new Vector();
        private boolean _editable = false;
        
        public ParameterTableModel() {
        }
        
        public void setEditable(boolean editable) {
            _editable = editable;
        }
        
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return _editable;
        }
        
        public synchronized void setParameters(String[][] params) {
            _data.removeAllElements();
            for (int i=0; i<params.length; i++) {
                if (params[i].length != 3) {
                    System.err.println("ParameterTableModel called with invalid data! Only got " +
                    params[i].length + " entries in parameter " + i);
                } else {
                    _data.add(params[i]);
                }
            }
            fireTableDataChanged();
        }
        
        public synchronized String[][] getParameters() {
            int rows = 0;
            for (int i = 0; i < _data.size(); i++) {
                String[] row = (String[]) _data.get(i);
                if (!row[0].equals("") && !row[1].equals("")) {
                    rows++;
                }
            }
            String[][] params = new String[rows][3];
            rows = 0;
            for (int i = 0; i < _data.size(); i++) {
                String[] row = (String[]) _data.get(i);
                if (!row[0].equals("") && !row[1].equals("")) {
                    params[rows][0] = row[0];
                    params[rows][1] = row[1];
                    params[rows][2] = row[2];
                    rows++;
                }
            }
            return params;
        }
        
        public synchronized void clear() {
            _data.removeAllElements();
            fireTableDataChanged();
        }
        
        public synchronized void insertRow(int rowIndex) {
            _data.insertElementAt(new String[] {"","",""}, rowIndex);
            fireTableRowsInserted(rowIndex,rowIndex);
        }
        
        public synchronized void deleteRow(int rowIndex) {
            _data.removeElementAt(rowIndex);
            fireTableRowsDeleted(rowIndex, rowIndex);
        }
        
        public String getColumnName(int column) {
            if (column < _columnNames.length) {
                return _columnNames[column];
            }
            return "";
        }
        
        public synchronized int getColumnCount() {
            return _columnNames.length;
        }
        
        public synchronized int getRowCount() {
            return _data.size();
        }
        
        public synchronized Object getValueAt(int row, int column) {
            if (row<0 || row > _data.size()) {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : row does not exist!");
            }
            String[] rowdata = (String[]) _data.get(row);
            if (column <= _columnNames.length) {
                return rowdata[column];
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to get row " + row + ", column " + column + " : column does not exist!");
            }
        }
        
        public synchronized void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            String[] rowdata = (String[]) _data.get(rowIndex);
            if (rowIndex<0 || rowIndex > _data.size()) {
                throw new ArrayIndexOutOfBoundsException("Attempt to set row " + rowIndex + ", column " + columnIndex + " to " + aValue + " : row does not exist!");
            }
            if (columnIndex <= _columnNames.length) {
                rowdata[columnIndex] = (String) aValue;
                fireTableCellUpdated(rowIndex, columnIndex);
            } else {
                throw new ArrayIndexOutOfBoundsException("Attempt to set row " + rowIndex + ", column " + columnIndex + " to " + aValue + " : column does not exist!");
            }
        }
    }
    
}
