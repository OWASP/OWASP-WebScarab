/**
 * *********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security Project
 * utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2010 FedICT Copyright (c) 2010 Frank Cornelis
 * <info@frankcornelis.be>
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at Sourceforge.net, a repository
 * for free software projects.
 *
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */
package org.owasp.webscarab.plugin.saml.swing;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;
import javax.swing.Action;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.plugin.saml.Occurences;
import org.owasp.webscarab.plugin.saml.Saml;
import org.owasp.webscarab.plugin.saml.SamlCertificateRepository;
import org.owasp.webscarab.plugin.saml.SamlModel;
import org.owasp.webscarab.plugin.saml.SamlProxy;
import org.owasp.webscarab.plugin.saml.SamlProxyListener;
import org.owasp.webscarab.plugin.saml.SamlSignatureException;
import org.owasp.webscarab.plugin.saml.SignatureType;
import org.owasp.webscarab.plugin.saml.Wrapper;
import org.owasp.webscarab.ui.swing.CertificateManager;
import org.owasp.webscarab.ui.swing.ColumnWidthTracker;
import org.owasp.webscarab.ui.swing.ConversationTableModel;
import org.owasp.webscarab.ui.swing.ShowConversationAction;
import org.owasp.webscarab.ui.swing.SwingPluginUI;
import org.owasp.webscarab.util.swing.ColumnDataModel;
import org.owasp.webscarab.util.swing.TableSorter;
import org.owasp.webscarab.util.swing.TreeUtil;

/**
 * WebScarab SAML plugin UI.
 *
 * @author Frank Cornelis
 */
public class SamlPanel extends javax.swing.JPanel implements SwingPluginUI, SamlProxyListener {

    private Logger _logger = Logger.getLogger(getClass().getName());
    private final Saml saml;
    private final SamlModel samlModel;
    private final ShowConversationAction showConversationAction;
    private final SamlReplayConversationAction samlReplayConversationAction;
    private final SamlExportConversationAction samlExportConversationAction;
    private final OpenBrowserAction openBrowserAction;
    private final AttributesTableModel attributesTableModel;
    private final AttributesTableModel injectAttributesTableModel;
    private final AttributesTableModel encryptedAttributesTableModel;
    private final SamlCertificateRepository samlCertificateRepository;
    private final CertificateManager certificateManager;

    /**
     * Creates new form SamlPanel
     */
    public SamlPanel(Saml saml) {
        this.saml = saml;
        this.samlModel = saml.getModel();
        initComponents();

        ConversationTableModel samlTableModel = new ConversationTableModel(
                this.samlModel.getSamlConversationModel());
        ColumnWidthTracker.getTracker("SAMLTable").addTable(this.samlTable);
        samlTableModel.addColumn(new ColumnDataModel<ConversationID>("SAML Type", String.class) {
            @Override
            public Object getValue(ConversationID key) {
                return SamlPanel.this.samlModel.getSAMLType(key);
            }
        });
        TableSorter sorterSamlTableModel = new TableSorter(samlTableModel);
        this.samlTable.setModel(sorterSamlTableModel);

        this.showConversationAction = new ShowConversationAction(this.samlModel.getSamlConversationModel());
        this.samlPopupMenu.add(new JMenuItem(this.showConversationAction));
        this.samlReplayConversationAction = new SamlReplayConversationAction(this.saml.getSamlProxy());
        this.samlPopupMenu.add(new JMenuItem(this.samlReplayConversationAction));
        this.samlExportConversationAction = new SamlExportConversationAction(this.saml.getModel());
        this.samlPopupMenu.add(new JMenuItem(this.samlExportConversationAction));
        this.openBrowserAction = new OpenBrowserAction(this.saml.getModel());
        this.samlPopupMenu.add(new JMenuItem(this.openBrowserAction));

        this.saml.getSamlProxy().addSamlProxyListener(this);

        this.attributesTableModel = new AttributesTableModel();
        this.attributesTable.setModel(this.attributesTableModel);

        this.injectAttributesTableModel = new AttributesTableModel();
        this.injectAttributesTable.setModel(this.injectAttributesTableModel);

        this.encryptedAttributesTableModel = new AttributesTableModel();
        this.encryptedAttributesTable.setModel(this.encryptedAttributesTableModel);

        this.samlCertificateRepository = new SamlCertificateRepository();
        this.samlCertificateRepository.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent event) {
                String propertyName = event.getPropertyName();
                if (propertyName.equals(SamlCertificateRepository.SELECTED_KEY)) {
                    String fingerprint = (String) event.getNewValue();
                    SamlPanel.this.keyTextField.setText(fingerprint);
                } else if (propertyName.equals(SamlCertificateRepository.SELECTED_KEY_ENTRY)) {
                    PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) event.getNewValue();
                    SamlPanel.this.saml.getSamlProxy().setPrivateKeyEntry(privateKeyEntry);
                }
            }
        });
        this.certificateManager = new CertificateManager(this.samlCertificateRepository);

        addTableListeners();
        addTreeListeners();
        resetDisplay();
    }

    private void addTreeListeners() {
        this.certPathTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        this.certPathTree.addTreeSelectionListener(new TreeSelectionListener() {
            @Override
            public void valueChanged(TreeSelectionEvent e) {
                Object node = SamlPanel.this.certPathTree.getLastSelectedPathComponent();
                if (null == node) {
                    return;
                }
                if (node instanceof CertPathTreeModel.TreeNode) {
                    CertPathTreeModel.TreeNode treeNode = (CertPathTreeModel.TreeNode) node;
                    X509Certificate certificate = treeNode.getCertificate();
                    SamlPanel.this.certDetailTextPanel.setText(null, certificate.toString());
                }
            }
        });
    }

    private void addTableListeners() {
        this.samlTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) {
                    return;
                }
                int row = SamlPanel.this.samlTable.getSelectedRow();
                TableModel tm = SamlPanel.this.samlTable.getModel();
                ConversationID id;
                if (row > -1) {
                    id = (ConversationID) tm.getValueAt(
                            row, 0); // UGLY hack! FIXME!!!!
                    SamlPanel.this.displaySaml(id);
                } else {
                    id = null;
                    SamlPanel.this.resetDisplay();
                }
                SamlPanel.this.showConversationAction.putValue("CONVERSATION", id);
                boolean samlResponse = SamlPanel.this.samlModel.isSAMLResponse(id);
                ConversationID samlResponseId;
                if (samlResponse) {
                    samlResponseId = id;
                } else {
                    samlResponseId = null;
                }
                SamlPanel.this.samlReplayConversationAction.putValue("SAML-RESPONSE", samlResponseId);
                SamlPanel.this.samlExportConversationAction.putValue("CONVERSATION", id);
                SamlPanel.this.openBrowserAction.putValue("CONVERSATION", id);
            }
        });

        this.samlTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }

            private void maybeShowPopup(MouseEvent e) {
                int row = SamlPanel.this.samlTable.rowAtPoint(e.getPoint());
                SamlPanel.this.samlTable.getSelectionModel().setSelectionInterval(row, row);
                if (e.isPopupTrigger()) {
                    SamlPanel.this.samlPopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
                    ActionEvent actionEvent = new ActionEvent(SamlPanel.this.samlTable, 0, (String) SamlPanel.this.showConversationAction.getValue(Action.ACTION_COMMAND_KEY));
                    SamlPanel.this.showConversationAction.actionPerformed(actionEvent);
                }
            }
        });
        
        this.injectAttributesTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int row = SamlPanel.this.injectAttributesTable.getSelectedRow();
                if (row > -1) {
                    SamlPanel.this.removeInjectAttributeButton.setEnabled(true);
                } else {
                    SamlPanel.this.removeInjectAttributeButton.setEnabled(false);
                }
            }
        });
        
        this.injectAttributesTableModel.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                SamlPanel.this._logger.fine("injectAttributesTableModel changed");
                SamlProxy samlProxy = SamlPanel.this.saml.getSamlProxy();
                samlProxy.setInjectionAttributes(SamlPanel.this.injectAttributesTableModel.getAttributes());
            }
        });
    }

    private void resetDisplay() {
        this.rawPanel.setText(null, "");
        this.textPanel.setText(null, "");
        this.xmlPanel.setBytes(null, null);
        this.relayStatePanel.setText(null, "");

        this.certDetailTextPanel.setText(null, "");
        this.signatureValidityLabel.setText("");
        this.certPathTree.setModel(
                new DefaultTreeModel(new DefaultMutableTreeNode("No certificate path")));

        this.htmlFormConversationIdLabel.setText("Unknown");
        this.htmlFormTextPanel.setText(null, "");
        this.htmlFormXmlPanel.setBytes(null, null);
        this.browserPostSslCheckBox.setSelected(false);
        this.htmlFormSslCheckBox.setSelected(false);
        this.signedMessageCheckBox.setSelected(false);

        this.samlVersionLabel.setText("Unknown");
        this.destinationIndicationCheckBox.setSelected(false);
        this.assertionsDigestedCheckBox.setSelected(false);
        this.validityIntervalIndicationCheckBox.setSelected(false);

        this.attributesTableModel.resetAttributes();
        this.encryptedAttributesTableModel.resetAttributes();
    }

    private void displaySaml(ConversationID id) {
        resetDisplay();
        String encodedSamlMessage = this.samlModel.getEncodedSAMLMessage(id);
        this.rawPanel.setText(null, encodedSamlMessage);
        String decodedSamlMessage = this.samlModel.getDecodedSAMLMessage(encodedSamlMessage);
        this.textPanel.setText(null, decodedSamlMessage);
        this.xmlPanel.setBytes("text/xml", decodedSamlMessage.getBytes());
        String relayState = this.samlModel.getRelayState(id);
        this.relayStatePanel.setText(null, relayState);

        displaySignature(id);

        ConversationID htmlFormConversationID = this.samlModel.findCorrespondingHTMLFormConversation(id);
        if (null == htmlFormConversationID) {
            this.htmlFormConversationIdLabel.setText("Not found");
        } else {
            this.htmlFormConversationIdLabel.setText(htmlFormConversationID.toString());
            byte[] content = this.samlModel.getResponseContent(htmlFormConversationID);
            this.htmlFormTextPanel.setBytes("UTF-8", content);
            this.htmlFormXmlPanel.setBytes("text/html", content);
            this.browserPostSslCheckBox.setSelected(this.samlModel.isOverSSL(id));
            this.htmlFormSslCheckBox.setSelected(this.samlModel.isOverSSL(htmlFormConversationID));
        }

        int samlVersion = this.samlModel.getSAMLVersion(id);
        String samlVersionStr;
        switch (samlVersion) {
            case SamlModel.SAML_VERSION_1_1:
                samlVersionStr = "1.1";
                break;
            case SamlModel.SAML_VERSION_2:
                samlVersionStr = "2.0";
                break;
            default:
                samlVersionStr = "Unknown";
                break;
        }
        this.samlVersionLabel.setText(samlVersionStr);

        this.destinationIndicationCheckBox.setSelected(this.samlModel.hasDestinationIndication(id));
        this.assertionsDigestedCheckBox.setSelected(this.samlModel.protocolSignatureDigestsAssertions(id));
        this.validityIntervalIndicationCheckBox.setSelected(this.samlModel.hasValidityIntervalIndication(id));

        this.attributesTableModel.setAttributes(this.samlModel.getSAMLAttributes(id));
        if (this.samlModel.hasEncryptedAttributes(id)) {
            this.decryptButton.setEnabled(true);
        } else {
            this.decryptButton.setEnabled(false);
        }
    }

    private void displaySignature(ConversationID id) {
        List<X509Certificate> certificateChain;
        try {
            certificateChain = this.samlModel.verifySAMLProtocolSignature(id);
        } catch (SamlSignatureException ex) {
            this.signatureValidityLabel.setText(ex.getMessage());
            this.signedMessageCheckBox.setSelected(false);
            return;
        }
        this.signatureValidityLabel.setText("valid");
        this.signedMessageCheckBox.setSelected(true);
        this.certPathTree.setModel(new CertPathTreeModel(certificateChain));
        TreeUtil.expandAll(this.certPathTree, true);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        samlPopupMenu = new javax.swing.JPopupMenu();
        subjectButtonGroup = new javax.swing.ButtonGroup();
        wrapperButtonGroup = new javax.swing.ButtonGroup();
        signatureButtonGroup = new javax.swing.ButtonGroup();
        attributeButtonGroup = new javax.swing.ButtonGroup();
        jSplitPane1 = new javax.swing.JSplitPane();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        rawPanel = new org.owasp.webscarab.ui.swing.editors.TextPanel();
        textPanel = new org.owasp.webscarab.ui.swing.editors.TextPanel();
        xmlPanel = new org.owasp.webscarab.ui.swing.editors.XMLPanel();
        signaturePanel = new javax.swing.JPanel();
        jSplitPane2 = new javax.swing.JSplitPane();
        jPanel2 = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        certDetailTextPanel = new org.owasp.webscarab.ui.swing.editors.TextPanel();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        certPathTree = new javax.swing.JTree();
        jPanel4 = new javax.swing.JPanel();
        jLabel6 = new javax.swing.JLabel();
        signatureValidityLabel = new javax.swing.JLabel();
        attributesPanel = new javax.swing.JPanel();
        jScrollPane3 = new javax.swing.JScrollPane();
        attributesTable = new javax.swing.JTable();
        encryptedAttributesPanel = new javax.swing.JPanel();
        jPanel29 = new javax.swing.JPanel();
        jLabel22 = new javax.swing.JLabel();
        attributeKeyTextField = new javax.swing.JTextField();
        decryptButton = new javax.swing.JButton();
        jScrollPane4 = new javax.swing.JScrollPane();
        encryptedAttributesTable = new javax.swing.JTable();
        htmlFormPanel = new javax.swing.JPanel();
        jPanel5 = new javax.swing.JPanel();
        jLabel7 = new javax.swing.JLabel();
        htmlFormConversationIdLabel = new javax.swing.JLabel();
        jTabbedPane2 = new javax.swing.JTabbedPane();
        htmlFormTextPanel = new org.owasp.webscarab.ui.swing.editors.TextPanel();
        htmlFormXmlPanel = new org.owasp.webscarab.ui.swing.editors.XMLPanel();
        relayStatePanel = new org.owasp.webscarab.ui.swing.editors.TextPanel();
        analysisPanel = new javax.swing.JPanel();
        analysisDataPanel = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        browserPostSslCheckBox = new javax.swing.JCheckBox();
        jLabel9 = new javax.swing.JLabel();
        htmlFormSslCheckBox = new javax.swing.JCheckBox();
        jLabel10 = new javax.swing.JLabel();
        signedMessageCheckBox = new javax.swing.JCheckBox();
        jLabel11 = new javax.swing.JLabel();
        samlVersionLabel = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        destinationIndicationCheckBox = new javax.swing.JCheckBox();
        jLabel13 = new javax.swing.JLabel();
        assertionsDigestedCheckBox = new javax.swing.JCheckBox();
        jLabel18 = new javax.swing.JLabel();
        validityIntervalIndicationCheckBox = new javax.swing.JCheckBox();
        aboutPanel = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        jTabbedPane3 = new javax.swing.JTabbedPane();
        jPanel8 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        samlTable = new javax.swing.JTable();
        jPanel6 = new javax.swing.JPanel();
        jPanel10 = new javax.swing.JPanel();
        jPanel7 = new javax.swing.JPanel();
        jPanel11 = new javax.swing.JPanel();
        corruptSignatureCheckBox = new javax.swing.JCheckBox();
        removeSignatureCheckBox = new javax.swing.JCheckBox();
        removeAssertionSignatureCheckBox = new javax.swing.JCheckBox();
        jPanel13 = new javax.swing.JPanel();
        jPanel14 = new javax.swing.JPanel();
        injectRemoteReferenceCheckBox = new javax.swing.JCheckBox();
        jLabel14 = new javax.swing.JLabel();
        injectionUriTextField = new javax.swing.JTextField();
        jPanel27 = new javax.swing.JPanel();
        jPanel28 = new javax.swing.JPanel();
        signCheckBox = new javax.swing.JCheckBox();
        jLabel21 = new javax.swing.JLabel();
        selectKeyButton = new javax.swing.JButton();
        keyTextField = new javax.swing.JTextField();
        jPanel30 = new javax.swing.JPanel();
        jPanel32 = new javax.swing.JPanel();
        signWrapAttackCheckBox = new javax.swing.JCheckBox();
        jPanel35 = new javax.swing.JPanel();
        protocolSignatureRadioButton = new javax.swing.JRadioButton();
        assertionSignatureRadioButton = new javax.swing.JRadioButton();
        jPanel34 = new javax.swing.JPanel();
        dsObjectWrapperRadioButton = new javax.swing.JRadioButton();
        samlpExtWrapperRadioButton = new javax.swing.JRadioButton();
        duplicateAssertionRadioButton = new javax.swing.JRadioButton();
        jPanel33 = new javax.swing.JPanel();
        renameIdCheckBox = new javax.swing.JCheckBox();
        renameAssertionIdCheckBox = new javax.swing.JCheckBox();
        renameLastAssertionIdCheckBox = new javax.swing.JCheckBox();
        jPanel19 = new javax.swing.JPanel();
        jPanel20 = new javax.swing.JPanel();
        jPanel15 = new javax.swing.JPanel();
        jPanel36 = new javax.swing.JPanel();
        injectAttributeCheckBox = new javax.swing.JCheckBox();
        jScrollPane6 = new javax.swing.JScrollPane();
        injectAttributesTable = new javax.swing.JTable();
        jPanel37 = new javax.swing.JPanel();
        addInjectAttributeButton = new javax.swing.JButton();
        removeInjectAttributeButton = new javax.swing.JButton();
        jPanel16 = new javax.swing.JPanel();
        jLabel15 = new javax.swing.JLabel();
        allAttributeRadioButton = new javax.swing.JRadioButton();
        firstAttributeRadioButton = new javax.swing.JRadioButton();
        lastAttributeRadioButton = new javax.swing.JRadioButton();
        jPanel17 = new javax.swing.JPanel();
        jPanel18 = new javax.swing.JPanel();
        injectSubjectCheckBox = new javax.swing.JCheckBox();
        jLabel17 = new javax.swing.JLabel();
        injectionSubjectTextField = new javax.swing.JTextField();
        jPanel31 = new javax.swing.JPanel();
        allSubjectRadioButton = new javax.swing.JRadioButton();
        firstSubjectRadioButton = new javax.swing.JRadioButton();
        lastSubjectRadioButton = new javax.swing.JRadioButton();
        jLabel23 = new javax.swing.JLabel();
        jPanel23 = new javax.swing.JPanel();
        jPanel24 = new javax.swing.JPanel();
        injectPublicDoctypeCheckBox = new javax.swing.JCheckBox();
        jLabel19 = new javax.swing.JLabel();
        dtdUriTextField = new javax.swing.JTextField();
        jPanel25 = new javax.swing.JPanel();
        jPanel26 = new javax.swing.JPanel();
        injectRelayStateCheckBox = new javax.swing.JCheckBox();
        jLabel20 = new javax.swing.JLabel();
        relayStateTextField = new javax.swing.JTextField();
        jPanel21 = new javax.swing.JPanel();
        jPanel22 = new javax.swing.JPanel();
        jPanel9 = new javax.swing.JPanel();
        jPanel12 = new javax.swing.JPanel();
        samlReplayCheckBox = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        samlReplayLabel = new javax.swing.JLabel();

        setLayout(new java.awt.BorderLayout());

        jSplitPane1.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);
        jSplitPane1.setResizeWeight(0.5);

        jTabbedPane1.addTab("Raw", rawPanel);
        jTabbedPane1.addTab("Text", textPanel);
        jTabbedPane1.addTab("XML", xmlPanel);

        signaturePanel.setLayout(new java.awt.BorderLayout());

        jSplitPane2.setResizeWeight(0.5);

        jPanel2.setLayout(new java.awt.BorderLayout());

        jLabel5.setText("Certificate Details");
        jPanel2.add(jLabel5, java.awt.BorderLayout.PAGE_START);
        jPanel2.add(certDetailTextPanel, java.awt.BorderLayout.CENTER);

        jSplitPane2.setRightComponent(jPanel2);

        jPanel3.setLayout(new java.awt.BorderLayout());

        certPathTree.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificate Path"));
        jScrollPane2.setViewportView(certPathTree);

        jPanel3.add(jScrollPane2, java.awt.BorderLayout.CENTER);

        jPanel4.setLayout(new javax.swing.BoxLayout(jPanel4, javax.swing.BoxLayout.LINE_AXIS));

        jLabel6.setText("Protocol Signature Validity: ");
        jPanel4.add(jLabel6);

        signatureValidityLabel.setText("Unknown");
        jPanel4.add(signatureValidityLabel);

        jPanel3.add(jPanel4, java.awt.BorderLayout.PAGE_START);

        jSplitPane2.setLeftComponent(jPanel3);

        signaturePanel.add(jSplitPane2, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("Protocol Signature", signaturePanel);

        attributesPanel.setLayout(new java.awt.BorderLayout());

        attributesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane3.setViewportView(attributesTable);

        attributesPanel.add(jScrollPane3, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("Attributes", attributesPanel);

        encryptedAttributesPanel.setLayout(new java.awt.BorderLayout());

        jPanel29.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jLabel22.setText("AES-128 key (hex): ");
        jPanel29.add(jLabel22);

        attributeKeyTextField.setColumns(32);
        jPanel29.add(attributeKeyTextField);

        decryptButton.setText("Decrypt");
        decryptButton.setEnabled(false);
        decryptButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptButtonActionPerformed(evt);
            }
        });
        jPanel29.add(decryptButton);

        encryptedAttributesPanel.add(jPanel29, java.awt.BorderLayout.PAGE_START);

        encryptedAttributesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane4.setViewportView(encryptedAttributesTable);

        encryptedAttributesPanel.add(jScrollPane4, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("Encrypted Attributes", encryptedAttributesPanel);

        htmlFormPanel.setLayout(new java.awt.BorderLayout());

        jPanel5.setLayout(new javax.swing.BoxLayout(jPanel5, javax.swing.BoxLayout.LINE_AXIS));

        jLabel7.setText("Corresponding HTML Form Conversation ID: ");
        jPanel5.add(jLabel7);

        htmlFormConversationIdLabel.setText("Unknown");
        jPanel5.add(htmlFormConversationIdLabel);

        htmlFormPanel.add(jPanel5, java.awt.BorderLayout.PAGE_START);

        jTabbedPane2.addTab("Text", htmlFormTextPanel);
        jTabbedPane2.addTab("XML", htmlFormXmlPanel);

        htmlFormPanel.add(jTabbedPane2, java.awt.BorderLayout.CENTER);

        jTabbedPane1.addTab("HTML Form", htmlFormPanel);
        jTabbedPane1.addTab("Relay State", relayStatePanel);

        analysisPanel.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        analysisDataPanel.setLayout(new java.awt.GridBagLayout());

        jLabel8.setText("SAML Browser POST over SSL:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel8, gridBagConstraints);

        browserPostSslCheckBox.setToolTipText("Prevents a MITM attack");
        browserPostSslCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(browserPostSslCheckBox, gridBagConstraints);

        jLabel9.setText("Corresponding HTML Form over SSL:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel9, gridBagConstraints);

        htmlFormSslCheckBox.setToolTipText("Prevents a MITM attack");
        htmlFormSslCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(htmlFormSslCheckBox, gridBagConstraints);

        jLabel10.setText("Signed SAML Message:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel10, gridBagConstraints);

        signedMessageCheckBox.setToolTipText("Prevents identity forgery");
        signedMessageCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(signedMessageCheckBox, gridBagConstraints);

        jLabel11.setText("SAML Version:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel11, gridBagConstraints);

        samlVersionLabel.setText("Unknown");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(samlVersionLabel, gridBagConstraints);

        jLabel12.setText("Destination indication:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 4;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel12, gridBagConstraints);

        destinationIndicationCheckBox.setToolTipText("Indicates whether the SAML message has some indication of its intended destination");
        destinationIndicationCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 4;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(destinationIndicationCheckBox, gridBagConstraints);

        jLabel13.setText("Assertions digested:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 5;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel13, gridBagConstraints);

        assertionsDigestedCheckBox.setToolTipText("Checks whether all SAML Assertions are digested by the SAML protocol XML signature");
        assertionsDigestedCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 5;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(assertionsDigestedCheckBox, gridBagConstraints);

        jLabel18.setText("Validity Interval indication:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 6;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(jLabel18, gridBagConstraints);

        validityIntervalIndicationCheckBox.setToolTipText("Checks whether the Conditions @NotBefore and @NotOnOrAfter are present.");
        validityIntervalIndicationCheckBox.setEnabled(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 6;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        analysisDataPanel.add(validityIntervalIndicationCheckBox, gridBagConstraints);

        analysisPanel.add(analysisDataPanel);

        jTabbedPane1.addTab("Analysis", analysisPanel);

        aboutPanel.setLayout(new java.awt.GridBagLayout());

        jLabel2.setText("WebScarab SAML Plugin");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.insets = new java.awt.Insets(0, 0, 19, 0);
        aboutPanel.add(jLabel2, gridBagConstraints);

        jLabel3.setText("Copyright (C) 2010-2012 FedICT");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        aboutPanel.add(jLabel3, gridBagConstraints);

        jLabel4.setText("Copyright (C) 2010-2011 Frank Cornelis <info@frankcornelis.be>");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        aboutPanel.add(jLabel4, gridBagConstraints);

        jTabbedPane1.addTab("About", aboutPanel);

        jSplitPane1.setRightComponent(jTabbedPane1);

        jPanel1.setLayout(new java.awt.BorderLayout());

        jPanel8.setLayout(new java.awt.BorderLayout());

        samlTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(samlTable);

        jPanel8.add(jScrollPane1, java.awt.BorderLayout.CENTER);

        jTabbedPane3.addTab("SAML Browser POST Profile Messages", jPanel8);

        jPanel6.setBorder(null);
        jPanel6.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel10.setLayout(new java.awt.GridBagLayout());

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder("Signature Integrity Attacks"));
        jPanel7.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel11.setLayout(new java.awt.GridBagLayout());

        corruptSignatureCheckBox.setText("Corrupt SAML Response Signature");
        corruptSignatureCheckBox.setToolTipText("Changes the DigestValue of the first ds:Reference element");
        corruptSignatureCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                corruptSignatureCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel11.add(corruptSignatureCheckBox, gridBagConstraints);

        removeSignatureCheckBox.setText("Remove SAML Response Signature");
        removeSignatureCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                removeSignatureCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel11.add(removeSignatureCheckBox, gridBagConstraints);

        removeAssertionSignatureCheckBox.setText("Remove SAML Assertion Signature");
        removeAssertionSignatureCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                removeAssertionSignatureCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel11.add(removeAssertionSignatureCheckBox, gridBagConstraints);

        jPanel7.add(jPanel11);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel10.add(jPanel7, gridBagConstraints);

        jPanel13.setBorder(javax.swing.BorderFactory.createTitledBorder("Signature Remote Attack"));
        jPanel13.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel14.setLayout(new java.awt.GridBagLayout());

        injectRemoteReferenceCheckBox.setText("Inject Reference URI in SAML Response Signature");
        injectRemoteReferenceCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                injectRemoteReferenceCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel14.add(injectRemoteReferenceCheckBox, gridBagConstraints);

        jLabel14.setText("Injected URI: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel14.add(jLabel14, gridBagConstraints);

        injectionUriTextField.setColumns(20);
        injectionUriTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                injectionUriTextFieldActionPerformed(evt);
            }
        });
        injectionUriTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                injectionUriTextFieldFocusLost(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel14.add(injectionUriTextField, gridBagConstraints);

        jPanel13.add(jPanel14);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel10.add(jPanel13, gridBagConstraints);

        jPanel27.setBorder(javax.swing.BorderFactory.createTitledBorder("Signature Trust Attack"));

        jPanel28.setLayout(new java.awt.GridBagLayout());

        signCheckBox.setText("Resign SAML protocol message");
        signCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                signCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel28.add(signCheckBox, gridBagConstraints);

        jLabel21.setText("Key: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel28.add(jLabel21, gridBagConstraints);

        selectKeyButton.setText("Select Key...");
        selectKeyButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selectKeyButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_END;
        gridBagConstraints.insets = new java.awt.Insets(5, 0, 0, 0);
        jPanel28.add(selectKeyButton, gridBagConstraints);

        keyTextField.setColumns(20);
        keyTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel28.add(keyTextField, gridBagConstraints);

        jPanel27.add(jPanel28);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel10.add(jPanel27, gridBagConstraints);

        jPanel6.add(jPanel10);

        jTabbedPane3.addTab("Signature Attacks", jPanel6);

        jPanel30.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel32.setLayout(new java.awt.GridBagLayout());

        signWrapAttackCheckBox.setText("Signature Wrapping Attack");
        signWrapAttackCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                signWrapAttackCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel32.add(signWrapAttackCheckBox, gridBagConstraints);

        jPanel35.setBorder(javax.swing.BorderFactory.createTitledBorder("Signature"));
        jPanel35.setLayout(new javax.swing.BoxLayout(jPanel35, javax.swing.BoxLayout.PAGE_AXIS));

        signatureButtonGroup.add(protocolSignatureRadioButton);
        protocolSignatureRadioButton.setSelected(true);
        protocolSignatureRadioButton.setText("SAML protocol signature");
        protocolSignatureRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                protocolSignatureRadioButtonItemStateChanged(evt);
            }
        });
        jPanel35.add(protocolSignatureRadioButton);

        signatureButtonGroup.add(assertionSignatureRadioButton);
        assertionSignatureRadioButton.setText("SAML assertion signature");
        assertionSignatureRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                assertionSignatureRadioButtonItemStateChanged(evt);
            }
        });
        jPanel35.add(assertionSignatureRadioButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel32.add(jPanel35, gridBagConstraints);

        jPanel34.setBorder(javax.swing.BorderFactory.createTitledBorder("Wrapper Element"));
        jPanel34.setLayout(new javax.swing.BoxLayout(jPanel34, javax.swing.BoxLayout.PAGE_AXIS));

        wrapperButtonGroup.add(dsObjectWrapperRadioButton);
        dsObjectWrapperRadioButton.setSelected(true);
        dsObjectWrapperRadioButton.setText("ds:Object");
        dsObjectWrapperRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                dsObjectWrapperRadioButtonItemStateChanged(evt);
            }
        });
        jPanel34.add(dsObjectWrapperRadioButton);

        wrapperButtonGroup.add(samlpExtWrapperRadioButton);
        samlpExtWrapperRadioButton.setText("samlp:Extensions");
        samlpExtWrapperRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                samlpExtWrapperRadioButtonItemStateChanged(evt);
            }
        });
        jPanel34.add(samlpExtWrapperRadioButton);

        wrapperButtonGroup.add(duplicateAssertionRadioButton);
        duplicateAssertionRadioButton.setText("Duplicate Assertion");
        duplicateAssertionRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                duplicateAssertionRadioButtonItemStateChanged(evt);
            }
        });
        jPanel34.add(duplicateAssertionRadioButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        jPanel32.add(jPanel34, gridBagConstraints);

        jPanel33.setBorder(javax.swing.BorderFactory.createTitledBorder("References Settings"));
        jPanel33.setLayout(new javax.swing.BoxLayout(jPanel33, javax.swing.BoxLayout.PAGE_AXIS));

        renameIdCheckBox.setText("Rename top Response Id");
        renameIdCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                renameIdCheckBoxItemStateChanged(evt);
            }
        });
        jPanel33.add(renameIdCheckBox);

        renameAssertionIdCheckBox.setText("Rename first Assertion ID");
        renameAssertionIdCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                renameAssertionIdCheckBoxItemStateChanged(evt);
            }
        });
        jPanel33.add(renameAssertionIdCheckBox);

        renameLastAssertionIdCheckBox.setText("Rename last Assertion ID");
        renameLastAssertionIdCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                renameLastAssertionIdCheckBoxItemStateChanged(evt);
            }
        });
        jPanel33.add(renameLastAssertionIdCheckBox);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.VERTICAL;
        jPanel32.add(jPanel33, gridBagConstraints);

        jPanel30.add(jPanel32);

        jTabbedPane3.addTab("Signature Wrapping Attacks", jPanel30);

        jPanel19.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel20.setLayout(new java.awt.GridBagLayout());

        jPanel15.setBorder(javax.swing.BorderFactory.createTitledBorder("Attribute Injection Attack"));
        jPanel15.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel36.setLayout(new java.awt.GridBagLayout());

        injectAttributeCheckBox.setText("Change Attribute");
        injectAttributeCheckBox.setToolTipText("Changes the given attribute value on the SAML assertions");
        injectAttributeCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                injectAttributeCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel36.add(injectAttributeCheckBox, gridBagConstraints);

        jScrollPane6.setPreferredSize(new java.awt.Dimension(250, 100));

        injectAttributesTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        injectAttributesTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane6.setViewportView(injectAttributesTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        jPanel36.add(jScrollPane6, gridBagConstraints);

        jPanel37.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        addInjectAttributeButton.setText("Add...");
        addInjectAttributeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addInjectAttributeButtonActionPerformed(evt);
            }
        });
        jPanel37.add(addInjectAttributeButton);

        removeInjectAttributeButton.setText("Remove");
        removeInjectAttributeButton.setEnabled(false);
        removeInjectAttributeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeInjectAttributeButtonActionPerformed(evt);
            }
        });
        jPanel37.add(removeInjectAttributeButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel36.add(jPanel37, gridBagConstraints);

        jLabel15.setText("Occurences:");
        jPanel16.add(jLabel15);

        attributeButtonGroup.add(allAttributeRadioButton);
        allAttributeRadioButton.setSelected(true);
        allAttributeRadioButton.setText("All");
        allAttributeRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                allAttributeRadioButtonItemStateChanged(evt);
            }
        });
        jPanel16.add(allAttributeRadioButton);

        attributeButtonGroup.add(firstAttributeRadioButton);
        firstAttributeRadioButton.setText("First");
        firstAttributeRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                firstAttributeRadioButtonItemStateChanged(evt);
            }
        });
        jPanel16.add(firstAttributeRadioButton);

        attributeButtonGroup.add(lastAttributeRadioButton);
        lastAttributeRadioButton.setText("Last");
        lastAttributeRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                lastAttributeRadioButtonItemStateChanged(evt);
            }
        });
        jPanel16.add(lastAttributeRadioButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel36.add(jPanel16, gridBagConstraints);

        jPanel15.add(jPanel36);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.gridheight = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.FIRST_LINE_START;
        jPanel20.add(jPanel15, gridBagConstraints);

        jPanel17.setBorder(javax.swing.BorderFactory.createTitledBorder("Subject Injection Attack"));
        jPanel17.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel18.setLayout(new java.awt.GridBagLayout());

        injectSubjectCheckBox.setText("Change Subject");
        injectSubjectCheckBox.setToolTipText("Changes the subject within the SAML assertions.");
        injectSubjectCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                injectSubjectCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel18.add(injectSubjectCheckBox, gridBagConstraints);

        jLabel17.setText("Subject: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel18.add(jLabel17, gridBagConstraints);

        injectionSubjectTextField.setColumns(20);
        injectionSubjectTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                injectionSubjectTextFieldActionPerformed(evt);
            }
        });
        injectionSubjectTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                injectionSubjectTextFieldFocusLost(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        jPanel18.add(injectionSubjectTextField, gridBagConstraints);

        jPanel31.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        subjectButtonGroup.add(allSubjectRadioButton);
        allSubjectRadioButton.setSelected(true);
        allSubjectRadioButton.setText("All");
        allSubjectRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                allSubjectRadioButtonItemStateChanged(evt);
            }
        });
        jPanel31.add(allSubjectRadioButton);

        subjectButtonGroup.add(firstSubjectRadioButton);
        firstSubjectRadioButton.setText("First");
        firstSubjectRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                firstSubjectRadioButtonItemStateChanged(evt);
            }
        });
        jPanel31.add(firstSubjectRadioButton);

        subjectButtonGroup.add(lastSubjectRadioButton);
        lastSubjectRadioButton.setText("Last");
        lastSubjectRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                lastSubjectRadioButtonItemStateChanged(evt);
            }
        });
        jPanel31.add(lastSubjectRadioButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.LINE_START;
        jPanel18.add(jPanel31, gridBagConstraints);

        jLabel23.setText("Occurences:");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        jPanel18.add(jLabel23, gridBagConstraints);

        jPanel17.add(jPanel18);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel20.add(jPanel17, gridBagConstraints);

        jPanel23.setBorder(javax.swing.BorderFactory.createTitledBorder("DTD Injection Attack"));
        jPanel23.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel24.setLayout(new java.awt.GridBagLayout());

        injectPublicDoctypeCheckBox.setText("Inject PUBLIC DOCTYPE");
        injectPublicDoctypeCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                injectPublicDoctypeCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel24.add(injectPublicDoctypeCheckBox, gridBagConstraints);

        jLabel19.setText("DTD URI: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel24.add(jLabel19, gridBagConstraints);

        dtdUriTextField.setColumns(20);
        dtdUriTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dtdUriTextFieldActionPerformed(evt);
            }
        });
        dtdUriTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                dtdUriTextFieldFocusLost(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        jPanel24.add(dtdUriTextField, gridBagConstraints);

        jPanel23.add(jPanel24);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel20.add(jPanel23, gridBagConstraints);

        jPanel25.setBorder(javax.swing.BorderFactory.createTitledBorder("Relay State Injection Attack"));
        jPanel25.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel26.setLayout(new java.awt.GridBagLayout());

        injectRelayStateCheckBox.setText("Change Response Relay State");
        injectRelayStateCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                injectRelayStateCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel26.add(injectRelayStateCheckBox, gridBagConstraints);

        jLabel20.setText("Relay State: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel26.add(jLabel20, gridBagConstraints);

        relayStateTextField.setColumns(20);
        relayStateTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                relayStateTextFieldActionPerformed(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        jPanel26.add(relayStateTextField, gridBagConstraints);

        jPanel25.add(jPanel26);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel20.add(jPanel25, gridBagConstraints);

        jPanel19.add(jPanel20);

        jTabbedPane3.addTab("Injection Attacks", jPanel19);

        jPanel21.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel22.setLayout(new java.awt.GridBagLayout());

        jPanel9.setBorder(javax.swing.BorderFactory.createTitledBorder("SAML Response Replay Attack"));
        jPanel9.setLayout(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT));

        jPanel12.setLayout(new java.awt.GridBagLayout());

        samlReplayCheckBox.setText("SAML Response replay");
        samlReplayCheckBox.setToolTipText("Performs a replay attack using a previous selected SAML Response");
        samlReplayCheckBox.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                samlReplayCheckBoxItemStateChanged(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        jPanel12.add(samlReplayCheckBox, gridBagConstraints);

        jLabel1.setText("SAML Response used for replay: ");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        jPanel12.add(jLabel1, gridBagConstraints);

        samlReplayLabel.setText("None");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        jPanel12.add(samlReplayLabel, gridBagConstraints);

        jPanel9.add(jPanel12);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        jPanel22.add(jPanel9, gridBagConstraints);

        jPanel21.add(jPanel22);

        jTabbedPane3.addTab("Replay Attacks", jPanel21);

        jPanel1.add(jTabbedPane3, java.awt.BorderLayout.PAGE_START);

        jSplitPane1.setLeftComponent(jPanel1);

        add(jSplitPane1, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    private void corruptSignatureCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_corruptSignatureCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean corruptSignature = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setCorruptSignature(corruptSignature);
    }//GEN-LAST:event_corruptSignatureCheckBoxItemStateChanged

    private void removeSignatureCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_removeSignatureCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean removeSignature = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setRemoveSignature(removeSignature);
    }//GEN-LAST:event_removeSignatureCheckBoxItemStateChanged

    private void samlReplayCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_samlReplayCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean replay = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setReplay(replay);
    }//GEN-LAST:event_samlReplayCheckBoxItemStateChanged

    private void injectRemoteReferenceCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_injectRemoteReferenceCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean injectRemoteReference = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setInjectRemoteReference(injectRemoteReference);
    }//GEN-LAST:event_injectRemoteReferenceCheckBoxItemStateChanged

    private void injectionUriTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_injectionUriTextFieldActionPerformed
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String remoteReference = this.injectionUriTextField.getText();
        samlProxy.setRemoteReference(remoteReference);
    }//GEN-LAST:event_injectionUriTextFieldActionPerformed

    private void injectAttributeCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_injectAttributeCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean injectAttribute = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setInjectAttribute(injectAttribute);
    }//GEN-LAST:event_injectAttributeCheckBoxItemStateChanged

    private void injectSubjectCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_injectSubjectCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean injectSubject = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setInjectSubject(injectSubject);
    }//GEN-LAST:event_injectSubjectCheckBoxItemStateChanged

    private void injectionSubjectTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_injectionSubjectTextFieldActionPerformed
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String injectionSubject = this.injectionSubjectTextField.getText();
        samlProxy.setInjectionSubject(injectionSubject);
    }//GEN-LAST:event_injectionSubjectTextFieldActionPerformed

    private void injectionSubjectTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_injectionSubjectTextFieldFocusLost
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String injectionSubject = this.injectionSubjectTextField.getText();
        samlProxy.setInjectionSubject(injectionSubject);
    }//GEN-LAST:event_injectionSubjectTextFieldFocusLost

    private void injectionUriTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_injectionUriTextFieldFocusLost
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String remoteReference = this.injectionUriTextField.getText();
        samlProxy.setRemoteReference(remoteReference);
    }//GEN-LAST:event_injectionUriTextFieldFocusLost

    private void injectPublicDoctypeCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_injectPublicDoctypeCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean injectPublicDoctype = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setInjectPublicDoctype(injectPublicDoctype);
    }//GEN-LAST:event_injectPublicDoctypeCheckBoxItemStateChanged

    private void dtdUriTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dtdUriTextFieldActionPerformed
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String dtdUri = this.dtdUriTextField.getText();
        samlProxy.setDtdUri(dtdUri);
    }//GEN-LAST:event_dtdUriTextFieldActionPerformed

    private void dtdUriTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_dtdUriTextFieldFocusLost
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String dtdUri = this.dtdUriTextField.getText();
        samlProxy.setDtdUri(dtdUri);
    }//GEN-LAST:event_dtdUriTextFieldFocusLost

    private void injectRelayStateCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_injectRelayStateCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean injectRelayState = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setInjectRelayState(injectRelayState);
    }//GEN-LAST:event_injectRelayStateCheckBoxItemStateChanged

    private void relayStateTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_relayStateTextFieldActionPerformed
        SamlProxy samlProxy = this.saml.getSamlProxy();
        String relayState = this.relayStateTextField.getText();
        samlProxy.setRelayState(relayState);
    }//GEN-LAST:event_relayStateTextFieldActionPerformed

    private void selectKeyButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selectKeyButtonActionPerformed
        this.certificateManager.setVisible(true);
    }//GEN-LAST:event_selectKeyButtonActionPerformed

    private void signCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_signCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean signSamlMessage = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setSignSamlMessage(signSamlMessage);
    }//GEN-LAST:event_signCheckBoxItemStateChanged

    private void decryptButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptButtonActionPerformed
        try {
            ConversationID id = (ConversationID) this.showConversationAction.getValue("CONVERSATION");
            String hexKey = this.attributeKeyTextField.getText();
            List samlAttributes = this.samlModel.getDecryptedAttributes(id, hexKey);
            this.encryptedAttributesTableModel.setAttributes(samlAttributes);
        } catch (Exception ex) {
            this.encryptedAttributesTableModel.resetAttributes();
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Decryption error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_decryptButtonActionPerformed

    private void signWrapAttackCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_signWrapAttackCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean signWrapAttack = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setSignWrapAttack(signWrapAttack);
    }//GEN-LAST:event_signWrapAttackCheckBoxItemStateChanged

    private void allSubjectRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_allSubjectRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean allOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (allOccurences) {
            samlProxy.setSubjectOccurences(Occurences.ALL);
        }
    }//GEN-LAST:event_allSubjectRadioButtonItemStateChanged

    private void firstSubjectRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_firstSubjectRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean firstOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (firstOccurences) {
            samlProxy.setSubjectOccurences(Occurences.FIRST);
        }
    }//GEN-LAST:event_firstSubjectRadioButtonItemStateChanged

    private void lastSubjectRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_lastSubjectRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean lastOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (lastOccurences) {
            samlProxy.setSubjectOccurences(Occurences.LAST);
        }
    }//GEN-LAST:event_lastSubjectRadioButtonItemStateChanged

    private void renameIdCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_renameIdCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean renameTopId = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setRenameTopId(renameTopId);
    }//GEN-LAST:event_renameIdCheckBoxItemStateChanged

    private void removeAssertionSignatureCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_removeAssertionSignatureCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean removeAssertionSignature = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setRemoveAssertionSignature(removeAssertionSignature);
    }//GEN-LAST:event_removeAssertionSignatureCheckBoxItemStateChanged

    private void dsObjectWrapperRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_dsObjectWrapperRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean dsObjectWrapper = evt.getStateChange() == ItemEvent.SELECTED;
        if (dsObjectWrapper) {
            samlProxy.setWrapper(Wrapper.DS_OBJECT);
        }
    }//GEN-LAST:event_dsObjectWrapperRadioButtonItemStateChanged

    private void samlpExtWrapperRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_samlpExtWrapperRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean samlpExtWrapper = evt.getStateChange() == ItemEvent.SELECTED;
        if (samlpExtWrapper) {
            samlProxy.setWrapper(Wrapper.SAMLP_EXTENSIONS);
        }
    }//GEN-LAST:event_samlpExtWrapperRadioButtonItemStateChanged

    private void protocolSignatureRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_protocolSignatureRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean protocolSignature = evt.getStateChange() == ItemEvent.SELECTED;
        if (protocolSignature) {
            samlProxy.setWrapperTargetSignature(SignatureType.PROTOCOL);
        }
    }//GEN-LAST:event_protocolSignatureRadioButtonItemStateChanged

    private void assertionSignatureRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_assertionSignatureRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean assertionSignature = evt.getStateChange() == ItemEvent.SELECTED;
        if (assertionSignature) {
            samlProxy.setWrapperTargetSignature(SignatureType.ASSERTION);
        }
    }//GEN-LAST:event_assertionSignatureRadioButtonItemStateChanged

    private void renameAssertionIdCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_renameAssertionIdCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean renameAssertionId = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setRenameAssertionId(renameAssertionId);
    }//GEN-LAST:event_renameAssertionIdCheckBoxItemStateChanged

    private void duplicateAssertionRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_duplicateAssertionRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean duplicateAssertion = evt.getStateChange() == ItemEvent.SELECTED;
        if (duplicateAssertion) {
            samlProxy.setWrapper(Wrapper.ASSERTION);
        }
    }//GEN-LAST:event_duplicateAssertionRadioButtonItemStateChanged

    private void addInjectAttributeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addInjectAttributeButtonActionPerformed
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();

        JLabel nameLabel = new JLabel("Name:");
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.ipadx = 10;
        panel.add(nameLabel, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField nameTextField = new JTextField(20);
        panel.add(nameTextField, gridBagConstraints);

        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy++;
        JLabel valueLabel = new JLabel("Value:");
        panel.add(valueLabel, gridBagConstraints);

        gridBagConstraints.gridx++;
        JTextField valueTextField = new JTextField(20);
        panel.add(valueTextField, gridBagConstraints);

        int result = JOptionPane.showConfirmDialog(this, panel, "Inject attribute", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            if (false == nameTextField.getText().isEmpty()) {
                this.injectAttributesTableModel.addAttribute(nameTextField.getText(), valueTextField.getText());
            }
        }
    }//GEN-LAST:event_addInjectAttributeButtonActionPerformed

    private void removeInjectAttributeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeInjectAttributeButtonActionPerformed
        int row = this.injectAttributesTable.getSelectedRow();
        this.injectAttributesTableModel.removeAttribute(row);
        this.removeInjectAttributeButton.setEnabled(false);
    }//GEN-LAST:event_removeInjectAttributeButtonActionPerformed

    private void renameLastAssertionIdCheckBoxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_renameLastAssertionIdCheckBoxItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean renameLastAssertionId = evt.getStateChange() == ItemEvent.SELECTED;
        samlProxy.setRenameLastAssertionId(renameLastAssertionId);
    }//GEN-LAST:event_renameLastAssertionIdCheckBoxItemStateChanged

    private void allAttributeRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_allAttributeRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean allOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (allOccurences) {
            samlProxy.setAttributeOccurences(Occurences.ALL);
        }
    }//GEN-LAST:event_allAttributeRadioButtonItemStateChanged

    private void firstAttributeRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_firstAttributeRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean allOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (allOccurences) {
            samlProxy.setAttributeOccurences(Occurences.FIRST);
        }
    }//GEN-LAST:event_firstAttributeRadioButtonItemStateChanged

    private void lastAttributeRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_lastAttributeRadioButtonItemStateChanged
        SamlProxy samlProxy = this.saml.getSamlProxy();
        boolean allOccurences = evt.getStateChange() == ItemEvent.SELECTED;
        if (allOccurences) {
            samlProxy.setAttributeOccurences(Occurences.LAST);
        }
    }//GEN-LAST:event_lastAttributeRadioButtonItemStateChanged

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel aboutPanel;
    private javax.swing.JButton addInjectAttributeButton;
    private javax.swing.JRadioButton allAttributeRadioButton;
    private javax.swing.JRadioButton allSubjectRadioButton;
    private javax.swing.JPanel analysisDataPanel;
    private javax.swing.JPanel analysisPanel;
    private javax.swing.JRadioButton assertionSignatureRadioButton;
    private javax.swing.JCheckBox assertionsDigestedCheckBox;
    private javax.swing.ButtonGroup attributeButtonGroup;
    private javax.swing.JTextField attributeKeyTextField;
    private javax.swing.JPanel attributesPanel;
    private javax.swing.JTable attributesTable;
    private javax.swing.JCheckBox browserPostSslCheckBox;
    private org.owasp.webscarab.ui.swing.editors.TextPanel certDetailTextPanel;
    private javax.swing.JTree certPathTree;
    private javax.swing.JCheckBox corruptSignatureCheckBox;
    private javax.swing.JButton decryptButton;
    private javax.swing.JCheckBox destinationIndicationCheckBox;
    private javax.swing.JRadioButton dsObjectWrapperRadioButton;
    private javax.swing.JTextField dtdUriTextField;
    private javax.swing.JRadioButton duplicateAssertionRadioButton;
    private javax.swing.JPanel encryptedAttributesPanel;
    private javax.swing.JTable encryptedAttributesTable;
    private javax.swing.JRadioButton firstAttributeRadioButton;
    private javax.swing.JRadioButton firstSubjectRadioButton;
    private javax.swing.JLabel htmlFormConversationIdLabel;
    private javax.swing.JPanel htmlFormPanel;
    private javax.swing.JCheckBox htmlFormSslCheckBox;
    private org.owasp.webscarab.ui.swing.editors.TextPanel htmlFormTextPanel;
    private org.owasp.webscarab.ui.swing.editors.XMLPanel htmlFormXmlPanel;
    private javax.swing.JCheckBox injectAttributeCheckBox;
    private javax.swing.JTable injectAttributesTable;
    private javax.swing.JCheckBox injectPublicDoctypeCheckBox;
    private javax.swing.JCheckBox injectRelayStateCheckBox;
    private javax.swing.JCheckBox injectRemoteReferenceCheckBox;
    private javax.swing.JCheckBox injectSubjectCheckBox;
    private javax.swing.JTextField injectionSubjectTextField;
    private javax.swing.JTextField injectionUriTextField;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel17;
    private javax.swing.JLabel jLabel18;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel20;
    private javax.swing.JLabel jLabel21;
    private javax.swing.JLabel jLabel22;
    private javax.swing.JLabel jLabel23;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel13;
    private javax.swing.JPanel jPanel14;
    private javax.swing.JPanel jPanel15;
    private javax.swing.JPanel jPanel16;
    private javax.swing.JPanel jPanel17;
    private javax.swing.JPanel jPanel18;
    private javax.swing.JPanel jPanel19;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel20;
    private javax.swing.JPanel jPanel21;
    private javax.swing.JPanel jPanel22;
    private javax.swing.JPanel jPanel23;
    private javax.swing.JPanel jPanel24;
    private javax.swing.JPanel jPanel25;
    private javax.swing.JPanel jPanel26;
    private javax.swing.JPanel jPanel27;
    private javax.swing.JPanel jPanel28;
    private javax.swing.JPanel jPanel29;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel30;
    private javax.swing.JPanel jPanel31;
    private javax.swing.JPanel jPanel32;
    private javax.swing.JPanel jPanel33;
    private javax.swing.JPanel jPanel34;
    private javax.swing.JPanel jPanel35;
    private javax.swing.JPanel jPanel36;
    private javax.swing.JPanel jPanel37;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPanel jPanel9;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSplitPane jSplitPane1;
    private javax.swing.JSplitPane jSplitPane2;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTabbedPane jTabbedPane2;
    private javax.swing.JTabbedPane jTabbedPane3;
    private javax.swing.JTextField keyTextField;
    private javax.swing.JRadioButton lastAttributeRadioButton;
    private javax.swing.JRadioButton lastSubjectRadioButton;
    private javax.swing.JRadioButton protocolSignatureRadioButton;
    private org.owasp.webscarab.ui.swing.editors.TextPanel rawPanel;
    private org.owasp.webscarab.ui.swing.editors.TextPanel relayStatePanel;
    private javax.swing.JTextField relayStateTextField;
    private javax.swing.JCheckBox removeAssertionSignatureCheckBox;
    private javax.swing.JButton removeInjectAttributeButton;
    private javax.swing.JCheckBox removeSignatureCheckBox;
    private javax.swing.JCheckBox renameAssertionIdCheckBox;
    private javax.swing.JCheckBox renameIdCheckBox;
    private javax.swing.JCheckBox renameLastAssertionIdCheckBox;
    private javax.swing.JPopupMenu samlPopupMenu;
    private javax.swing.JCheckBox samlReplayCheckBox;
    private javax.swing.JLabel samlReplayLabel;
    private javax.swing.JTable samlTable;
    private javax.swing.JLabel samlVersionLabel;
    private javax.swing.JRadioButton samlpExtWrapperRadioButton;
    private javax.swing.JButton selectKeyButton;
    private javax.swing.JCheckBox signCheckBox;
    private javax.swing.JCheckBox signWrapAttackCheckBox;
    private javax.swing.ButtonGroup signatureButtonGroup;
    private javax.swing.JPanel signaturePanel;
    private javax.swing.JLabel signatureValidityLabel;
    private javax.swing.JCheckBox signedMessageCheckBox;
    private javax.swing.ButtonGroup subjectButtonGroup;
    private org.owasp.webscarab.ui.swing.editors.TextPanel textPanel;
    private javax.swing.JCheckBox validityIntervalIndicationCheckBox;
    private javax.swing.ButtonGroup wrapperButtonGroup;
    private org.owasp.webscarab.ui.swing.editors.XMLPanel xmlPanel;
    // End of variables declaration//GEN-END:variables

    @Override
    public Action[] getConversationActions() {
        return null;
    }

    @Override
    public ColumnDataModel<ConversationID>[] getConversationColumns() {
        return null;
    }

    @Override
    public JPanel getPanel() {
        return this;
    }

    @Override
    public Action[] getUrlActions() {
        return null;
    }

    @Override
    public ColumnDataModel<HttpUrl>[] getUrlColumns() {
        return null;
    }

    @Override
    public String getPluginName() {
        return this.saml.getPluginName();
    }

    @Override
    public void replayChanged(ConversationID replayId) {
        this.samlReplayLabel.setText(replayId.toString());
    }
}
