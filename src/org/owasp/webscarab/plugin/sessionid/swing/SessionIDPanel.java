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
 * SessionIDPanel.java
 *
 * Created on 16 November 2003, 08:21
 */

package org.owasp.webscarab.plugin.sessionid.swing;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;

import org.owasp.webscarab.ui.swing.ConversationListModel;
import org.owasp.webscarab.ui.swing.ConversationRenderer;
import org.owasp.webscarab.ui.swing.RequestPanel;
import org.owasp.webscarab.ui.swing.ResponsePanel;
import org.owasp.webscarab.ui.swing.SwingPluginUI;

import org.owasp.webscarab.plugin.sessionid.SessionID;
import org.owasp.webscarab.plugin.sessionid.SessionIDAnalysis;
import org.owasp.webscarab.plugin.sessionid.SessionIDModel;
import org.owasp.webscarab.plugin.sessionid.SessionIDListener;

import org.owasp.webscarab.util.swing.ListComboBoxModel;
import org.owasp.webscarab.util.swing.SwingWorker;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.util.swing.ColumnDataModel;

import javax.swing.ListModel;
import javax.swing.ComboBoxModel;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.DefaultListModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import java.io.IOException;

import java.util.Date;
import java.util.Map;
import java.util.Iterator;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.jfree.chart.JFreeChart;
import org.jfree.chart.ChartPanel;
import org.jfree.data.XYDataset;
import org.jfree.data.AbstractSeriesDataset;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.StandardXYItemRenderer;

import javax.swing.table.AbstractTableModel;
import javax.swing.JOptionPane;

import java.math.BigInteger;
import java.lang.reflect.InvocationTargetException;

import java.text.SimpleDateFormat;

import java.util.regex.PatternSyntaxException;

/**
 *
 * @author  rdawes
 */
public class SessionIDPanel extends javax.swing.JPanel implements SwingPluginUI, SessionIDListener {
    
    private final RequestPanel _requestPanel;
    private final ResponsePanel _responsePanel;
    private JFreeChart _chart = null;
    
    private String _key = null;
    private SessionIDAnalysis _sa;
    private SessionIDDataset _sidd;
    private SessionIDTableModel _tableModel;
    private ConversationListModel _conversationList;
    
    private DefaultListModel _sessionIDNames = new DefaultListModel();
    
    private SessionIDModel _model;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates new form SessionIDPanel */
    public SessionIDPanel(SessionIDAnalysis sa) {
        _sa = sa;
        _model = _sa.getModel();
        
        initComponents();
        
        mainTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                mainTabbedPaneStateChanged(e);
            }
        });
        _requestPanel = new RequestPanel();
        _requestPanel.selectPanel("Raw");
        _requestPanel.setBorder(new javax.swing.border.TitledBorder("Request"));
        _requestPanel.setEditable(true);
        _requestPanel.setRequest(null);
        
        _responsePanel = new ResponsePanel();
        _responsePanel.setBorder(new javax.swing.border.TitledBorder("Response"));
        
        conversationSplitPane.setTopComponent(_requestPanel);
        conversationSplitPane.setBottomComponent(_responsePanel);
        
        _sessionIDNames.clear();
        for (int i=0; i<_model.getSessionIDNameCount(); i++) {
            _sessionIDNames.addElement(_model.getSessionIDName(i));
        }
        
        requestComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Object o = requestComboBox.getSelectedItem();
                if (o instanceof ConversationID) {
                    ConversationID id = (ConversationID) o;
                    Request r = _model.getRequest(id);
                    _requestPanel.setEditable(true);
                    _requestPanel.setRequest(r);
                    _responsePanel.setEditable(false);
                    _responsePanel.setResponse(null);
                }
            }
        });
        
        _tableModel = new SessionIDTableModel();
        _sidd = new SessionIDDataset();
        
        _sidd.fireDatasetChanged();
        _tableModel.fireTableDataChanged();
        
        nameComboBox.setModel(new ListComboBoxModel(_sessionIDNames));
        _model.addModelListener(this);
        
        idTable.setModel(new TableSorter(_tableModel, idTable.getTableHeader()));
        idTable.setDefaultRenderer(Date.class, new DateRenderer());
        
        _conversationList = new ConversationListModel(_model.getConversationModel());
        requestComboBox.setModel(new ListComboBoxModel(_conversationList));
        requestComboBox.setRenderer(new ConversationRenderer(_model.getConversationModel()));
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    private void initComponents() {//GEN-BEGIN:initComponents
        java.awt.GridBagConstraints gridBagConstraints;

        locationButtonGroup = new javax.swing.ButtonGroup();
        mainTabbedPane = new javax.swing.JTabbedPane();
        collectionPanel = new javax.swing.JPanel();
        specPanel = new javax.swing.JPanel();
        nameLabel = new javax.swing.JLabel();
        nameTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        regexTextField = new javax.swing.JTextField();
        bodyCheckBox = new javax.swing.JCheckBox();
        conversationPanel = new javax.swing.JPanel();
        conversationSplitPane = new javax.swing.JSplitPane();
        actionPanel = new javax.swing.JPanel();
        testButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        sampleSpinner = new javax.swing.JSpinner();
        fetchButton = new javax.swing.JButton();
        historyPanel = new javax.swing.JPanel();
        requestComboBox = new javax.swing.JComboBox();
        jLabel9 = new javax.swing.JLabel();
        analysisPanel = new javax.swing.JPanel();
        nameComboBox = new javax.swing.JComboBox();
        jLabel8 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        idTable = new javax.swing.JTable();
        visualisationPanel = new javax.swing.JPanel();

        setLayout(new java.awt.BorderLayout());

        collectionPanel.setLayout(new java.awt.GridBagLayout());

        specPanel.setLayout(new java.awt.GridBagLayout());

        specPanel.setToolTipText("Provide a name and regex to match a sessionid in the Location or body");
        nameLabel.setText("Name");
        nameLabel.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        specPanel.add(nameLabel, gridBagConstraints);

        nameTextField.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 3;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        specPanel.add(nameTextField, gridBagConstraints);

        jLabel2.setText("Regex");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        specPanel.add(jLabel2, gridBagConstraints);

        regexTextField.setToolTipText("The string enclosed in brackets is used as the session id");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        specPanel.add(regexTextField, gridBagConstraints);

        bodyCheckBox.setText("From message body");
        bodyCheckBox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        bodyCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bodyCheckBoxActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = 2;
        specPanel.add(bodyCheckBox, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        collectionPanel.add(specPanel, gridBagConstraints);

        conversationPanel.setLayout(new java.awt.BorderLayout());

        conversationSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        conversationSplitPane.setResizeWeight(0.5);
        conversationPanel.add(conversationSplitPane, java.awt.BorderLayout.CENTER);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        collectionPanel.add(conversationPanel, gridBagConstraints);

        testButton.setText("Test");
        testButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                testButtonActionPerformed(evt);
            }
        });

        actionPanel.add(testButton);

        jLabel3.setText("Samples");
        actionPanel.add(jLabel3);

        sampleSpinner.setMinimumSize(new java.awt.Dimension(61, 24));
        sampleSpinner.setPreferredSize(new java.awt.Dimension(61, 24));
        actionPanel.add(sampleSpinner);

        fetchButton.setText("Fetch");
        fetchButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                fetchButtonActionPerformed(evt);
            }
        });

        actionPanel.add(fetchButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.weightx = 0.5;
        collectionPanel.add(actionPanel, gridBagConstraints);

        historyPanel.setLayout(new java.awt.GridBagLayout());

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        historyPanel.add(requestComboBox, gridBagConstraints);

        jLabel9.setText("Previous Requests :");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        historyPanel.add(jLabel9, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        collectionPanel.add(historyPanel, gridBagConstraints);

        mainTabbedPane.addTab("Collection", collectionPanel);

        analysisPanel.setLayout(new java.awt.GridBagLayout());

        nameComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nameComboBoxActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        analysisPanel.add(nameComboBox, gridBagConstraints);

        jLabel8.setText("Session Identifier");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        analysisPanel.add(jLabel8, gridBagConstraints);

        idTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane1.setViewportView(idTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        analysisPanel.add(jScrollPane1, gridBagConstraints);

        mainTabbedPane.addTab("Analysis", analysisPanel);

        mainTabbedPane.addTab("Visualisation", visualisationPanel);

        add(mainTabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    private void bodyCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bodyCheckBoxActionPerformed
        nameLabel.setEnabled(bodyCheckBox.isSelected());
        nameTextField.setEnabled(bodyCheckBox.isSelected());
        if (!bodyCheckBox.isSelected()) nameTextField.setText("");
    }//GEN-LAST:event_bodyCheckBoxActionPerformed
    
    private void testButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_testButtonActionPerformed
        final Request request = _requestPanel.getRequest();
        if (request == null) {
            return;
        }
        testButton.setEnabled(false);
        final java.awt.Component parent = this;
        new SwingWorker() {
            public Object construct() {
                try {
                    _sa.setRequest(request);
                    _sa.fetchResponse();
                    return _sa.getResponse();
                } catch (IOException ioe) {
                    return ioe;
                }
            }
            
            //Runs on the event-dispatching thread.
            public void finished() {
                Object obj = getValue();
                if (obj instanceof Response) {
                    Response response = (Response) getValue();
                    if (response != null) {
                        _responsePanel.setResponse(response);
                        String name = nameTextField.getText();
                        String regex = regexTextField.getText();
                        try {
                            Map ids = _sa.getIDsFromResponse(response, name, regex);
                            String[] keys = (String[]) ids.keySet().toArray(new String[0]);
                            for (int i=0; i<keys.length; i++) {
                                SessionID id = (SessionID) ids.get(keys[i]);
                                keys[i] = id.getDate() + " : " + keys[i] + " = " + id.getValue();
                            }
                            if (keys.length == 0) keys = new String[] { "No session identifiers found!" };
                            JOptionPane.showMessageDialog(parent, keys, "Extracted Sessionids", JOptionPane.INFORMATION_MESSAGE);
                        } catch (PatternSyntaxException pse) {
                            JOptionPane.showMessageDialog(parent, pse.getMessage(), "Patter Syntax Exception", JOptionPane.WARNING_MESSAGE);
                        }
                    }
                } else if (obj instanceof Exception) {
                    JOptionPane.showMessageDialog(null, new String[] {"Error fetching response: ", obj.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                    _logger.severe("Exception fetching response: " + obj);
                }
                testButton.setEnabled(true);
            }
        }.start();
    }//GEN-LAST:event_testButtonActionPerformed
    
    private void mainTabbedPaneStateChanged(ChangeEvent evt) {
        int selected = mainTabbedPane.getSelectedIndex();
        if(mainTabbedPane.getTitleAt(selected).equals("Visualisation")) {
            if (_chart == null) { // subject to race condition!
                new SwingWorker() {
                    public Object construct() {
                        return createChart(_sidd);
                    }
                    
                    public void finished() {
                        _chart = (JFreeChart) get();
                        /* ineffective! WHY?! FIXME!!
                        _chart.getXYPlot().getDomainAxis().setAutoRange(true);
                        _chart.getXYPlot().getDomainAxis().setAutoTickUnitSelection(true);
                        _chart.getXYPlot().getDomainAxis().setTickLabelsVisible(true);
                         */
                        visualisationPanel.add(new ChartPanel(_chart, 900, 500, 600, 400, 1280, 1024, true, true, true, false, true, true));
                        visualisationPanel.doLayout();
                    }
                }.start();
            }
        }
    }
    
    private JFreeChart createChart(XYDataset data) {
        ValueAxis timeAxis = new DateAxis("Date/Time");
        timeAxis.setLowerMargin(0.02);  // reduce the default margins on the time axis
        timeAxis.setUpperMargin(0.02);
        NumberAxis valueAxis = new NumberAxis("Value");
        valueAxis.setAutoRangeIncludesZero(false);  // override default
        XYPlot plot = new XYPlot(data, timeAxis, valueAxis, null);
        plot.setRenderer(new StandardXYItemRenderer(StandardXYItemRenderer.SHAPES, null, null));
        JFreeChart chart = new JFreeChart("Cookie values over time", JFreeChart.DEFAULT_TITLE_FONT, plot, false);
        return chart;
    }
    
    private void nameComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nameComboBoxActionPerformed
        _key = (String)nameComboBox.getSelectedItem();
        _tableModel.fireTableDataChanged();
        _sidd.fireDatasetChanged();
    }//GEN-LAST:event_nameComboBoxActionPerformed
    
    private void fetchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fetchButtonActionPerformed
        Request request = _requestPanel.getRequest();
        if (request == null) {
            _logger.warning("Request was null in fetch request");
            return;
        }
        String name = nameTextField.getText();
        String regex = regexTextField.getText();
        int count = ((Integer)sampleSpinner.getValue()).intValue();
        try {
            _sa.fetch(request, name, regex, count);
        } catch (PatternSyntaxException pse) {
            JOptionPane.showMessageDialog(this, pse.getMessage(), "Patter Syntax Exception", JOptionPane.WARNING_MESSAGE);
        }
    }//GEN-LAST:event_fetchButtonActionPerformed
    
    public void sessionIDAdded(final String key, final int index) {
        if (SwingUtilities.isEventDispatchThread()) {
            if (index == 0) {
                _sessionIDNames.addElement(key);
            }
            if (key.equals(_key)) {
                _sidd.fireDatasetChanged();
                _tableModel.fireTableRowsInserted(index, index);
            }
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    sessionIDAdded(key, index);
                }
            });
        }
    }
    
    public void sessionIDsChanged() {
        if (SwingUtilities.isEventDispatchThread()) {
            _key = null;
            int count = _model.getSessionIDNameCount();
            for (int i=0; i<count; i++) {
                _sessionIDNames.addElement(_model.getSessionIDName(i));
            }
            _sidd.fireDatasetChanged();
            _tableModel.fireTableDataChanged();
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    sessionIDsChanged();
                }
            });
        }
    }
    
    public void calculatorChanged(final String key) {
        if (key.equals(_key)) {
            if (SwingUtilities.isEventDispatchThread()) {
                _sidd.fireDatasetChanged();
                _tableModel.fireTableDataChanged();
            } else {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        calculatorChanged(key);
                    }
                });
            }
        }
    }
    
    public javax.swing.JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "SessionID Analysis";
    }
    
    public javax.swing.Action[] getConversationActions() {
        return null;
    }
    
    public javax.swing.Action[] getUrlActions() {
        return null;
    }
    
    public void setEnabled(final boolean enabled) {
        if (SwingUtilities.isEventDispatchThread()) {
            mainTabbedPane.setEnabled(enabled);
            testButton.setEnabled(enabled);
            fetchButton.setEnabled(enabled);
            // FIXME do the rest
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    setEnabled(enabled);
                }
            });
        }
    }
    
    public ColumnDataModel[] getConversationColumns() {
        return null;
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return null;
    }
    
    public void pluginRunStatusChanged(boolean running, boolean stopping) {
    }
    
    public void pluginStatusChanged(String status) {
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel actionPanel;
    private javax.swing.JPanel analysisPanel;
    private javax.swing.JCheckBox bodyCheckBox;
    private javax.swing.JPanel collectionPanel;
    private javax.swing.JPanel conversationPanel;
    private javax.swing.JSplitPane conversationSplitPane;
    private javax.swing.JButton fetchButton;
    private javax.swing.JPanel historyPanel;
    private javax.swing.JTable idTable;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.ButtonGroup locationButtonGroup;
    private javax.swing.JTabbedPane mainTabbedPane;
    private javax.swing.JComboBox nameComboBox;
    private javax.swing.JLabel nameLabel;
    private javax.swing.JTextField nameTextField;
    private javax.swing.JTextField regexTextField;
    private javax.swing.JComboBox requestComboBox;
    private javax.swing.JSpinner sampleSpinner;
    private javax.swing.JPanel specPanel;
    private javax.swing.JButton testButton;
    private javax.swing.JPanel visualisationPanel;
    // End of variables declaration//GEN-END:variables
    
    private class DateRenderer extends DefaultTableCellRenderer {
        
        private SimpleDateFormat _sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        
        public DateRenderer() {
            super();
        }
        
        public void setValue(Object value) {
            if ((value != null) && (value instanceof Date)) {
                Date date = (Date) value;
                // value = DateUtil.rfc822Format(date);
                value = _sdf.format(date);
            }
            super.setValue(value);
        }
        
    }
    
    private class SessionIDDataset extends AbstractSeriesDataset implements XYDataset {
        
        public int getSeriesCount() {
            return 1;
        }
        
        public String getSeriesName(int param) {
            return "Cookie value";
        }
        
        public int getItemCount(int series) {
            if (_key == null) return 0;
            return _model.getSessionIDCount(_key);
        }
        
        public Number getXValue(int series, int item) {
            SessionID id = _model.getSessionIDAt(_key, item);
            return new Long(id.getDate().getTime());
        }
        
        public Number getYValue(int series, int item) {
            SessionID id = _model.getSessionIDAt(_key, item);
            BigInteger bi = _model.getSessionIDValue(_key, id);
            if (bi == null) {
                return new Double(0);
            } else {
                return new Double(bi.doubleValue());
            }
        }
        
        public void calculatorChanged(String key) {
            if (key.equals(_key)) fireDatasetChanged();
        }
        
        public void sessionIDAdded(String key, int index) {
            if (key.equals(_key)) fireDatasetChanged();
        }
        
        public void fireDatasetChanged() {
            super.fireDatasetChanged();
        }
        
    }
    
    public class SessionIDTableModel extends AbstractTableModel {
        
        private String[] _columnNames = new String[] { "Date", "Value", "Numeric", "Difference" };
        private Class[] _columnClass = new Class[] { Date.class, String.class, BigInteger.class, BigInteger.class };
        
        public int getColumnCount() {
            return _columnNames.length;
        }
        
        public int getRowCount() {
            if (_key == null) return 0;
            return _model.getSessionIDCount(_key);
        }
        
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (_key == null) return null;
            SessionID id = _model.getSessionIDAt(_key, rowIndex);
            switch(columnIndex) {
                case 0: return id.getDate();
                case 1: return id.getValue();
                case 2: return _model.getSessionIDValue(_key, id);
                case 3: 
                    if (rowIndex == 0) {
                        return null;
                    } else {
                        SessionID prev = _model.getSessionIDAt(_key, rowIndex - 1);
                        BigInteger prevValue = _model.getSessionIDValue(_key, prev);
                        BigInteger now = _model.getSessionIDValue(_key,  id);
                        if (now != null && prevValue != null) return now.subtract(prevValue);
                    };
                default: return null;
            }
        }
        
        public String getColumnName(int columnIndex) {
            return _columnNames[columnIndex];
        }
        
        public Class getColumnClass(int columnIndex) {
            return _columnClass[columnIndex];
        }
        
    }
    
}
