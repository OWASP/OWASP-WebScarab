/*
 * SessionIDPanel.java
 *
 * Created on 16 November 2003, 08:21
 */

package org.owasp.webscarab.ui.swing.sessionid;

import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.SiteModel;

import org.owasp.webscarab.ui.swing.SwingPlugin;
import org.owasp.webscarab.ui.swing.SwingWorker;
import org.owasp.webscarab.ui.swing.ListComboBoxModel;
import org.owasp.webscarab.ui.swing.RequestPanel;
import org.owasp.webscarab.ui.swing.ResponsePanel;
import org.owasp.webscarab.ui.Framework;

import org.owasp.webscarab.plugin.sessionid.SessionIDAnalysis;
import org.owasp.webscarab.plugin.sessionid.SessionID;

import org.owasp.webscarab.util.swing.ListTableModelAdaptor;
import org.owasp.webscarab.util.swing.TableRow;
import org.owasp.webscarab.util.swing.TableSorter;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;

import javax.swing.ListModel;
import javax.swing.ComboBoxModel;

import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import javax.swing.table.TableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import java.util.TreeMap;
import java.util.Date;
import java.util.logging.Logger;

import org.jfree.chart.JFreeChart;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.XYDataset;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.StandardXYItemRenderer;

/**
 *
 * @author  rdawes
 */
public class SessionIDPanel extends javax.swing.JPanel implements SwingPlugin, ListDataListener {
    
    private final RequestPanel _requestPanel;
    private final ResponsePanel _responsePanel;
    private JFreeChart _chart = null;
    
    private SessionIDAnalysis _sa;
    private ListTableModelAdaptor _ltma = new ListTableModelAdaptor(null, new SessionIDRow());
    private SessionIDDataset _sidd = new SessionIDDataset(null);
    
    private SiteModel _siteModel;
    
    private Logger _logger = Logger.getLogger(this.getClass().getName());
    
    /** Creates new form SessionIDPanel */
    public SessionIDPanel(Framework framework) {
        _sa = new SessionIDAnalysis(framework);
        framework.addPlugin(_sa);
        
        initComponents();
        
        mainTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
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
        });
        _requestPanel = new RequestPanel();
        _requestPanel.setEditable(true);
        _requestPanel.setBorder(new javax.swing.border.TitledBorder("Request"));
        Request req = new Request();
        try {
            req.setMethod("GET");
            req.setURL("http://localhost:8080/admin/");
            req.setMethod("HTTP/1.0");
        } catch (MalformedURLException mue) {}
        _requestPanel.setRequest(req);
        
        _responsePanel = new ResponsePanel();
        _responsePanel.setBorder(new javax.swing.border.TitledBorder("Response"));
        _responsePanel.setEditable(false);
        
        conversationSplitPane.setTopComponent(_requestPanel);
        conversationSplitPane.setBottomComponent(_responsePanel);
        nameComboBox.setModel(new ListComboBoxModel(_sa.getSessionIDNames()));
        idTable.setModel(new TableSorter(_ltma, idTable.getTableHeader()));
        idTable.setDefaultRenderer(Date.class, new DateRenderer());
        
        _siteModel = framework.getSiteModel();
        ListModel conversationList = _siteModel.getConversationListModel();
        ComboBoxModel requestModel = new ListComboBoxModel(conversationList);
        requestComboBox.setModel(requestModel);
        requestComboBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Object o = requestComboBox.getSelectedItem();
                if (o instanceof Conversation) {
                    Conversation c = (Conversation) o;
                    String id = c.getProperty("ID");
                    Request r = _siteModel.getRequest(id);
                    _requestPanel.setRequest(r);
                    _responsePanel.setResponse(null);
                }
            }
        });

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
        cookieRadioButton = new javax.swing.JRadioButton();
        bodyRadioButton = new javax.swing.JRadioButton();
        jLabel1 = new javax.swing.JLabel();
        nameTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        regexTextField = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        requestComboBox = new javax.swing.JComboBox();
        conversationPanel = new javax.swing.JPanel();
        conversationSplitPane = new javax.swing.JSplitPane();
        actionPanel = new javax.swing.JPanel();
        testButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        sampleSpinner = new javax.swing.JSpinner();
        fetchButton = new javax.swing.JButton();
        resultPanel = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        dateTextField = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        valueTextField = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        analysisPanel = new javax.swing.JPanel();
        nameComboBox = new javax.swing.JComboBox();
        jLabel8 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        idTable = new javax.swing.JTable();
        calculateButton = new javax.swing.JButton();
        visualisationPanel = new javax.swing.JPanel();

        setLayout(new java.awt.BorderLayout());

        collectionPanel.setLayout(new java.awt.GridBagLayout());

        specPanel.setLayout(new java.awt.GridBagLayout());

        cookieRadioButton.setSelected(true);
        cookieRadioButton.setText("Cookie");
        locationButtonGroup.add(cookieRadioButton);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        specPanel.add(cookieRadioButton, gridBagConstraints);

        bodyRadioButton.setText("Body");
        locationButtonGroup.add(bodyRadioButton);
        bodyRadioButton.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        specPanel.add(bodyRadioButton, gridBagConstraints);

        jLabel1.setText("Name");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        specPanel.add(jLabel1, gridBagConstraints);

        nameTextField.setText("localhost/ JSESSIONID");
        nameTextField.setToolTipText("use 'host.domain/path name' for cookies");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        specPanel.add(nameTextField, gridBagConstraints);

        jLabel2.setText("Regex");
        jLabel2.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        specPanel.add(jLabel2, gridBagConstraints);

        regexTextField.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        specPanel.add(regexTextField, gridBagConstraints);

        jLabel6.setText("Session ID Location");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        specPanel.add(jLabel6, gridBagConstraints);

        jLabel9.setText("Previous Requests :");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.insets = new java.awt.Insets(4, 4, 4, 4);
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        specPanel.add(jLabel9, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        specPanel.add(requestComboBox, gridBagConstraints);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        collectionPanel.add(specPanel, gridBagConstraints);

        conversationPanel.setLayout(new java.awt.BorderLayout());

        conversationSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        conversationSplitPane.setResizeWeight(0.5);
        conversationPanel.add(conversationSplitPane, java.awt.BorderLayout.CENTER);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
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
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        collectionPanel.add(actionPanel, gridBagConstraints);

        resultPanel.setLayout(new java.awt.GridBagLayout());

        jLabel4.setText("Date");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        resultPanel.add(jLabel4, gridBagConstraints);

        dateTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        resultPanel.add(dateTextField, gridBagConstraints);

        jLabel5.setText("Value");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        resultPanel.add(jLabel5, gridBagConstraints);

        valueTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        resultPanel.add(valueTextField, gridBagConstraints);

        jLabel7.setText("Results");
        resultPanel.add(jLabel7, new java.awt.GridBagConstraints());

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        collectionPanel.add(resultPanel, gridBagConstraints);

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

        calculateButton.setText("Calculate");
        calculateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                calculateButtonActionPerformed(evt);
            }
        });

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.gridwidth = 2;
        analysisPanel.add(calculateButton, gridBagConstraints);

        mainTabbedPane.addTab("Analysis", analysisPanel);

        mainTabbedPane.addTab("Visualisation", visualisationPanel);

        add(mainTabbedPane, java.awt.BorderLayout.CENTER);

    }//GEN-END:initComponents
    
    private void nameComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nameComboBoxActionPerformed
        String name = (String)nameComboBox.getSelectedItem();
        ListModel lm = _sa.getSessionIDList(name);
        _ltma.setListModel(lm);
        _sidd.setListModel(lm);
    }//GEN-LAST:event_nameComboBoxActionPerformed
    
    private void calculateButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_calculateButtonActionPerformed
        String name = (String)nameComboBox.getSelectedItem();
        if (name != null && !name.equals("")) {
            _sa.calculate(name);
        }
    }//GEN-LAST:event_calculateButtonActionPerformed
    
    private void fetchButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_fetchButtonActionPerformed
        Request request = _requestPanel.getRequest();
        if (request == null) {
            System.err.println("Request was null");
            return;
        }
        int location = -1;
        if (cookieRadioButton.isSelected()) {
            location = _sa.LOCATION_COOKIE;
        } else if (bodyRadioButton.isSelected()) {
            location = _sa.LOCATION_BODY;
        } else {
            System.err.println("invalid location");
            return;
        }
        int count = ((Integer)sampleSpinner.getValue()).intValue();
        System.out.println("Count = " + count);
        ListModel listModel = _sa.getSessionIDs(request, location, nameTextField.getText(), regexTextField.getText(), count);
        listModel.addListDataListener(this);
    }//GEN-LAST:event_fetchButtonActionPerformed
    
    private void testButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_testButtonActionPerformed
        final Request request = _requestPanel.getRequest();
        if (request == null) {
            return;
        }
        final int location;
        if (cookieRadioButton.isSelected()) {
            location = _sa.LOCATION_COOKIE;
        } else if (bodyRadioButton.isSelected()) {
            location = _sa.LOCATION_BODY;
        } else {
            location = -1;
        }
        testButton.setEnabled(false);
        new SwingWorker() {
            public Object construct() {
                try {
                    return _sa.fetchResponse(request);
                } catch (IOException ioe) {
                    return ioe.toString();
                }
            }
            
            //Runs on the event-dispatching thread.
            public void finished() {
                Object obj = getValue();
                if (obj instanceof Response) {
                    Response response = (Response) getValue();
                    if (response != null) {
                        _responsePanel.setResponse(response);
                        SessionID sessid = _sa.getIDfromResponse(response, location, nameTextField.getText(), regexTextField.getText());
                        if (sessid != null) {
                            dateTextField.setText(sessid.getDate().toString());
                            valueTextField.setText(sessid.getValue());
                        } else {
                            dateTextField.setText("");
                            valueTextField.setText("");
                        }
                    }
                } else if (obj instanceof String) {
                    JOptionPane.showMessageDialog(null, new String[] {"Error fetching response: ", obj.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                    _logger.severe("IOException fetching response: " + obj);
                }
                testButton.setEnabled(true);
            }
        }.start();
    }//GEN-LAST:event_testButtonActionPerformed
    
    public javax.swing.JPanel getPanel() {
        return this;
    }
    
    public String getPluginName() {
        return "SessionID Analysis";
    }
    
    public static void main(String[] args) {
        javax.swing.JFrame top = new javax.swing.JFrame("SessionID Analysis");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        javax.swing.JButton button = new javax.swing.JButton("GET");
        SessionIDPanel sp = new SessionIDPanel(new Framework());
        top.getContentPane().add(sp);
        top.setBounds(100,100,800,600);
        top.show();
    }
    
    public void contentsChanged(ListDataEvent e) {
    }
    
    public void intervalAdded(ListDataEvent e) {
        ListModel lm = (ListModel) e.getSource();
        final SessionID id = (SessionID) lm.getElementAt(lm.getSize()-1);
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                dateTextField.setText(id.getDate().toString());
                valueTextField.setText(id.getValue());
            }
        });
    }
    
    /** Sent after the indices in the index0,index1 interval
     * have been removed from the data model.  The interval
     * includes both index0 and index1.
     *
     * @param e  a <code>ListDataEvent</code> encapsulating the
     *    event information
     *
     */
    public void intervalRemoved(ListDataEvent e) {
    }
    
    public javax.swing.Action[] getConversationActions() {
        return null;
    }
    
    public javax.swing.Action[] getURLActions() {
        return null;
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel actionPanel;
    private javax.swing.JPanel analysisPanel;
    private javax.swing.JRadioButton bodyRadioButton;
    private javax.swing.JButton calculateButton;
    private javax.swing.JPanel collectionPanel;
    private javax.swing.JPanel conversationPanel;
    private javax.swing.JSplitPane conversationSplitPane;
    private javax.swing.JRadioButton cookieRadioButton;
    private javax.swing.JTextField dateTextField;
    private javax.swing.JButton fetchButton;
    private javax.swing.JTable idTable;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.ButtonGroup locationButtonGroup;
    private javax.swing.JTabbedPane mainTabbedPane;
    private javax.swing.JComboBox nameComboBox;
    private javax.swing.JTextField nameTextField;
    private javax.swing.JTextField regexTextField;
    private javax.swing.JComboBox requestComboBox;
    private javax.swing.JPanel resultPanel;
    private javax.swing.JSpinner sampleSpinner;
    private javax.swing.JPanel specPanel;
    private javax.swing.JButton testButton;
    private javax.swing.JTextField valueTextField;
    private javax.swing.JPanel visualisationPanel;
    // End of variables declaration//GEN-END:variables
    
    
    private class DateRenderer extends DefaultTableCellRenderer {
        
        public DateRenderer() {
            super();
        }
        
        public void setValue(Object value) {
            if ((value != null) && (value instanceof Date)) {
                Date date = (Date) value;
                value = value.toString();
            }
            super.setValue(value);
        }
        
    }

}
