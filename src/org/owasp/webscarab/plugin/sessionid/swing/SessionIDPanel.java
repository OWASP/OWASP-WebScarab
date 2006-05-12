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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;
import java.util.regex.PatternSyntaxException;
import javax.swing.JFileChooser;

import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Action;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;

import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.StandardXYItemRenderer;
import org.jfree.data.AbstractSeriesDataset;
import org.jfree.data.XYDataset;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.plugin.sessionid.SessionID;
import org.owasp.webscarab.plugin.sessionid.SessionIDAnalysis;
import org.owasp.webscarab.plugin.sessionid.SessionIDListener;
import org.owasp.webscarab.plugin.sessionid.SessionIDModel;
import org.owasp.webscarab.ui.swing.ConversationListModel;
import org.owasp.webscarab.ui.swing.ConversationRenderer;
import org.owasp.webscarab.ui.swing.DateRenderer;
import org.owasp.webscarab.ui.swing.RequestPanel;
import org.owasp.webscarab.ui.swing.ResponsePanel;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.ListComboBoxModel;
import org.owasp.webscarab.util.swing.SwingWorker;
import org.owasp.webscarab.util.swing.TableSorter;

/**
 *
 * @author  rdawes
 */
public class SessionIDPanel extends JPanel implements SwingPluginUI, SessionIDListener {
    
    private static final ColumnDataModel[] CDM = new ColumnDataModel[0];
    
    private final RequestPanel _requestPanel;
    private final ResponsePanel _responsePanel;
    private JFreeChart _chart = null;
    
    private String _key = null;
    private SessionIDAnalysis _sa;
    private SessionIDDataset _sidd;
    private SessionIDTableModel _tableModel;
    private ConversationListModel _conversationList;
    private Map _conversationColumns = new HashMap();
    private Map _urlColumns = new HashMap();
    
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
        _requestPanel.setBorder(new TitledBorder("Request"));
        _requestPanel.setEditable(true);
        _requestPanel.setRequest(null);
        
        _responsePanel = new ResponsePanel();
        _responsePanel.setBorder(new TitledBorder("Response"));
        
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
        createColumns();
    }
    
    private void createColumns() {
        ColumnDataModel cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getRequestCookies((ConversationID) key);
            }
            public String getColumnName() { return "Cookie"; }
            public Class getColumnClass() { return String.class; }
        };
        _conversationColumns.put("COOKIE", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                return _model.getResponseCookies((ConversationID) key);
            }
            public String getColumnName() { return "Set-Cookie"; }
            public Class getColumnClass() { return String.class; }
        };
        _conversationColumns.put("SET-COOKIE", cdm);
        
        cdm = new ColumnDataModel() {
            public Object getValue(Object key) {
                if (_model == null) return null;
                String value = _model.getResponseCookies((HttpUrl) key);
                return Boolean.valueOf(value != null);
            }
            public String getColumnName() { return "Set-Cookie"; }
            public Class getColumnClass() { return Boolean.class; }
        };
        _urlColumns.put("SET-COOKIE", cdm);
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
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
        jPanel1 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        nameComboBox = new javax.swing.JComboBox();
        jPanel2 = new javax.swing.JPanel();
        clearButton = new javax.swing.JButton();
        exportButton = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        idTable = new javax.swing.JTable();
        jPanel4 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        minTextField = new javax.swing.JTextField();
        maxTextField = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        rangeTextField = new javax.swing.JTextField();
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
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
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
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
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

        analysisPanel.setLayout(new java.awt.BorderLayout());

        jPanel1.setLayout(new java.awt.BorderLayout());

        jLabel8.setText("Session Identifier : ");
        jPanel1.add(jLabel8, java.awt.BorderLayout.WEST);

        nameComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nameComboBoxActionPerformed(evt);
            }
        });

        jPanel1.add(nameComboBox, java.awt.BorderLayout.CENTER);

        analysisPanel.add(jPanel1, java.awt.BorderLayout.NORTH);

        clearButton.setText("Clear");
        clearButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                clearButtonActionPerformed(evt);
            }
        });

        jPanel2.add(clearButton);

        exportButton.setText("Export");
        exportButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportButtonActionPerformed(evt);
            }
        });

        jPanel2.add(exportButton);

        analysisPanel.add(jPanel2, java.awt.BorderLayout.SOUTH);

        jPanel3.setLayout(new java.awt.BorderLayout());

        idTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jScrollPane1.setViewportView(idTable);

        jPanel3.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jPanel4.setLayout(new java.awt.GridBagLayout());

        jLabel1.setText("Minimum : ");
        jPanel4.add(jLabel1, new java.awt.GridBagConstraints());

        jLabel4.setText("Maximum : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        jPanel4.add(jLabel4, gridBagConstraints);

        minTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        jPanel4.add(minTextField, gridBagConstraints);

        maxTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        jPanel4.add(maxTextField, gridBagConstraints);

        jLabel5.setText("Range : ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        jPanel4.add(jLabel5, gridBagConstraints);

        rangeTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        jPanel4.add(rangeTextField, gridBagConstraints);

        jPanel3.add(jPanel4, java.awt.BorderLayout.SOUTH);

        analysisPanel.add(jPanel3, java.awt.BorderLayout.CENTER);

        mainTabbedPane.addTab("Analysis", analysisPanel);

        mainTabbedPane.addTab("Visualisation", visualisationPanel);

        add(mainTabbedPane, java.awt.BorderLayout.CENTER);

    }
    // </editor-fold>//GEN-END:initComponents
    
    private void exportButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportButtonActionPerformed
        if (_key == null) {
            JOptionPane.showMessageDialog(null, "Please select the Session ID to export, using the drop down list", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        JFileChooser jfc = new JFileChooser(Preferences.getPreference("WebScarab.DefaultDirectory"));
        jfc.setDialogTitle("Select a directory to write the sessionids into");
        int returnVal = jfc.showSaveDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            final File file = jfc.getSelectedFile();
            try {
                _sa.exportIDSToCSV(_key, file);
            } catch (IOException ioe) {
                JOptionPane.showMessageDialog(null, new String[] {"Error exporting session identifiers", ioe.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
        File dir = jfc.getCurrentDirectory();
        if (dir != null)
            Preferences.setPreference("WebScarab.DefaultDirectory", dir.getAbsolutePath());
    }//GEN-LAST:event_exportButtonActionPerformed
    
    private void clearButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_clearButtonActionPerformed
        if (_key == null) {
            JOptionPane.showMessageDialog(null, "Please select the Session ID to clear, using the drop down list", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        _sa.clearSessionIDs(_key);
    }//GEN-LAST:event_clearButtonActionPerformed
    
    private void bodyCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bodyCheckBoxActionPerformed
        nameLabel.setEnabled(bodyCheckBox.isSelected());
        nameTextField.setEnabled(bodyCheckBox.isSelected());
        if (!bodyCheckBox.isSelected()) nameTextField.setText("");
    }//GEN-LAST:event_bodyCheckBoxActionPerformed
    
    private void testButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_testButtonActionPerformed
        try {
            final Request request = _requestPanel.getRequest();
            if (request == null) {
                return;
            }
            testButton.setEnabled(false);
            final Component parent = this;
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
                                    keys[i] = keys[i] + " = " + id.getValue();
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
        } catch (MalformedURLException mue) {
            JOptionPane.showMessageDialog(this, new String[] {"The URL requested is malformed", mue.getMessage()}, "Malformed URL", JOptionPane.ERROR_MESSAGE);
        } 

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
        updateStats();
    }//GEN-LAST:event_nameComboBoxActionPerformed
    
    private void fetchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fetchButtonActionPerformed
        try {
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
                JOptionPane.showMessageDialog(this, pse.getMessage(), "Pattern Syntax Exception", JOptionPane.WARNING_MESSAGE);
            }
        } catch (MalformedURLException mue) {
            JOptionPane.showMessageDialog(this, new String[] {"The URL requested is malformed", mue.getMessage()}, "Malformed URL", JOptionPane.ERROR_MESSAGE);
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
            _sessionIDNames.clear();
            int count = _model.getSessionIDNameCount();
            for (int i=0; i<count; i++) {
                _sessionIDNames.addElement(_model.getSessionIDName(i));
            }
            _sidd.fireDatasetChanged();
            _tableModel.fireTableDataChanged();
            updateStats();
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    sessionIDsChanged();
                }
            });
        }
    }
    
    private void updateStats() {
        if (_key == null) {
            maxTextField.setText("");
            minTextField.setText("");
            rangeTextField.setText("");
            return;
        }
        BigInteger min = _model.getMinimumValue(_key);
        BigInteger max = _model.getMaximumValue(_key);
        if (min != null) {
            minTextField.setText(min.toString());
        } else {
            minTextField.setText("");
        }
        if (max != null) {
            maxTextField.setText(max.toString());
        } else {
            maxTextField.setText("");
        }
        if (min != null && max != null) {
            BigInteger range = max.subtract(min);
            rangeTextField.setText(Float.toString(range.floatValue()));
        } else {
            rangeTextField.setText("");
        }
    }
    
    public void calculatorChanged(final String key) {
        if (key.equals(_key)) {
            if (SwingUtilities.isEventDispatchThread()) {
                _sidd.fireDatasetChanged();
                _tableModel.fireTableDataChanged();
                updateStats();
            } else {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        calculatorChanged(key);
                    }
                });
            }
        }
    }
    
    public JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "SessionID Analysis";
    }
    
    public Action[] getConversationActions() {
        return null;
    }
    
    public Action[] getUrlActions() {
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
        return (ColumnDataModel[]) _conversationColumns.values().toArray(CDM);
    }
    
    public ColumnDataModel[] getUrlColumns() {
        return (ColumnDataModel[]) _urlColumns.values().toArray(CDM);
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel actionPanel;
    private javax.swing.JPanel analysisPanel;
    private javax.swing.JCheckBox bodyCheckBox;
    private javax.swing.JButton clearButton;
    private javax.swing.JPanel collectionPanel;
    private javax.swing.JPanel conversationPanel;
    private javax.swing.JSplitPane conversationSplitPane;
    private javax.swing.JButton exportButton;
    private javax.swing.JButton fetchButton;
    private javax.swing.JPanel historyPanel;
    private javax.swing.JTable idTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.ButtonGroup locationButtonGroup;
    private javax.swing.JTabbedPane mainTabbedPane;
    private javax.swing.JTextField maxTextField;
    private javax.swing.JTextField minTextField;
    private javax.swing.JComboBox nameComboBox;
    private javax.swing.JLabel nameLabel;
    private javax.swing.JTextField nameTextField;
    private javax.swing.JTextField rangeTextField;
    private javax.swing.JTextField regexTextField;
    private javax.swing.JComboBox requestComboBox;
    private javax.swing.JSpinner sampleSpinner;
    private javax.swing.JPanel specPanel;
    private javax.swing.JButton testButton;
    private javax.swing.JPanel visualisationPanel;
    // End of variables declaration//GEN-END:variables
    
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
                        if (now != null && prevValue != null) {
                            return now.subtract(prevValue);
                        } else {
                            return null;
                        }
                    }
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
