/*
 * CertificateManager.java
 *
 * Created on 12 January 2006, 01:05
 */

package org.owasp.webscarab.ui.swing;

import java.io.File;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.table.AbstractTableModel;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webscarab.httpclient.CertificateRepository;
import org.owasp.webscarab.httpclient.HTTPClientFactory;

/**
 *
 * @author  rdawes
 */
public class CertificateManager extends javax.swing.JFrame {
    
    /**
	 * 
	 */
	private static final long serialVersionUID = 5690492352598432340L;

	private CertificateRepository _certRepo;
    
    private DefaultListModel _keystoreListModel;
    private AliasTableModel _aliasTableModel;
    
     /** Creates new form CertificateManager */
    public CertificateManager() {
        this(HTTPClientFactory.getInstance().getSSLContextManager());
    }
    
    /** Creates new form CertificateManager */
    public CertificateManager(CertificateRepository certRepo) {
        this._certRepo = certRepo;
        initComponents();
        if (!_certRepo.isProviderAvailable("PKCS11"))
            keystoreTabbedPane.setEnabledAt(1, false);
        
        _keystoreListModel = new DefaultListModel();
        updateKeystoreList();
        keyStoreList.setModel(_keystoreListModel);
        keyStoreList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        keyStoreList.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                int keystore = keyStoreList.getSelectedIndex();
                try {
                    _aliasTableModel.setKeystore(keystore);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(null, new String[] {"Error accessing key store: ", e.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                    e.printStackTrace();
                }
            }
        });
        _aliasTableModel = new AliasTableModel();
        aliasTable.setModel(_aliasTableModel);
        aliasTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent evt) {
                _certRepo.setDefaultKey(null);
                int keystore = keyStoreList.getSelectedIndex();
                int alias = aliasTable.getSelectedRow();
                if (alias > -1) {
                    try {
                        Certificate cert = _certRepo.getCertificate(keystore, alias);
                        certTextArea.setText(cert.toString());
                        certTextArea.setCaretPosition(0);
                    } catch (Exception e) {
                        JOptionPane.showMessageDialog(null, new String[] {"Error accessing key store: ", e.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                        e.printStackTrace();
                    }
                } else {
                    certTextArea.setText("");
                }
            }
        });
        // stupid netbeans does not pack or resize child dialogs
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        addKeystoreDialog.setBounds((screenSize.width-450)/2, (screenSize.height-190)/2, 450, 190);
        // and the designer keeps resizing!
        setBounds((screenSize.width-600)/2, (screenSize.height-400)/2, 600, 400);
        
        // set default buttons
        getRootPane().setDefaultButton(closeButton);
        addKeystoreDialog.getRootPane().setDefaultButton(keystoreOkButton);
    }
    
    public String getPassword() {
        int result = JOptionPane.showConfirmDialog(this, askPasswordField, "Enter password", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            char[] password = askPasswordField.getPassword();
            if (password != null)
                return new String(password);
            return new String();
        } else return null;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        addKeystoreDialog = new javax.swing.JDialog(this);
        keystoreTabbedPane = new javax.swing.JTabbedPane();
        pkcs12Panel = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        pkcs12FileTextField = new javax.swing.JTextField();
        pkcs12BrowseButton = new javax.swing.JButton();
        pkcs12PasswordField = new javax.swing.JPasswordField();
        pkcs11Panel = new javax.swing.JPanel();
        jLabel5 = new javax.swing.JLabel();
        pkcs11NameTextField = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        pkcs11LibraryTextField = new javax.swing.JTextField();
        pkcs11BrowseButton = new javax.swing.JButton();
        jLabel10 = new javax.swing.JLabel();
        pkcs11SlotListIndexSpinner = new javax.swing.JSpinner();
        buttonPanel = new javax.swing.JPanel();
        keystoreCancelButton = new javax.swing.JButton();
        keystoreOkButton = new javax.swing.JButton();
        askPasswordField = new javax.swing.JPasswordField();
        jScrollPane1 = new javax.swing.JScrollPane();
        keyStoreList = new javax.swing.JList();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        aliasTable = new javax.swing.JTable();
        jPanel1 = new javax.swing.JPanel();
        addKeystoreButton = new javax.swing.JButton();
        setButton = new javax.swing.JButton();
        closeButton = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        certTextArea = new javax.swing.JTextArea();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        currentCertTextField = new javax.swing.JTextField();

        addKeystoreDialog.setTitle("Add Key Store");
        addKeystoreDialog.setModal(true);
        addKeystoreDialog.setResizable(false);

        pkcs12Panel.setLayout(new java.awt.GridBagLayout());

        jLabel3.setText("File");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs12Panel.add(jLabel3, gridBagConstraints);

        jLabel4.setText("Password");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs12Panel.add(jLabel4, gridBagConstraints);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        pkcs12Panel.add(pkcs12FileTextField, gridBagConstraints);

        pkcs12BrowseButton.setText("Browse");
        pkcs12BrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pkcs12BrowseButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs12Panel.add(pkcs12BrowseButton, gridBagConstraints);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        pkcs12Panel.add(pkcs12PasswordField, gridBagConstraints);

        keystoreTabbedPane.addTab("PKCS#12", pkcs12Panel);

        pkcs11Panel.setLayout(new java.awt.GridBagLayout());

        jLabel5.setText("Name");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs11Panel.add(jLabel5, gridBagConstraints);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        pkcs11Panel.add(pkcs11NameTextField, gridBagConstraints);

        jLabel6.setText("Library");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.EAST;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs11Panel.add(jLabel6, gridBagConstraints);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.weightx = 1.0;
        pkcs11Panel.add(pkcs11LibraryTextField, gridBagConstraints);

        pkcs11BrowseButton.setText("Browse");
        pkcs11BrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pkcs11BrowseButtonActionPerformed(evt);
            }
        });
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs11Panel.add(pkcs11BrowseButton, gridBagConstraints);

        jLabel10.setText("Slot List Index");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.insets = new java.awt.Insets(0, 4, 0, 4);
        pkcs11Panel.add(jLabel10, gridBagConstraints);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        pkcs11Panel.add(pkcs11SlotListIndexSpinner, gridBagConstraints);

        keystoreTabbedPane.addTab("PKCS#11", pkcs11Panel);

        addKeystoreDialog.getContentPane().add(keystoreTabbedPane, java.awt.BorderLayout.CENTER);

        keystoreCancelButton.setText("Cancel");
        keystoreCancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keystoreCancelButtonActionPerformed(evt);
            }
        });
        buttonPanel.add(keystoreCancelButton);

        keystoreOkButton.setText("Ok");
        keystoreOkButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keystoreOkButtonActionPerformed(evt);
            }
        });
        buttonPanel.add(keystoreOkButton);

        addKeystoreDialog.getContentPane().add(buttonPanel, java.awt.BorderLayout.SOUTH);

        setTitle("Certificate Manager");
        getContentPane().setLayout(new java.awt.GridBagLayout());

        jScrollPane1.setMinimumSize(new java.awt.Dimension(250, 22));
        jScrollPane1.setPreferredSize(new java.awt.Dimension(250, 176));
        jScrollPane1.setViewportView(keyStoreList);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weighty = 0.5;
        getContentPane().add(jScrollPane1, gridBagConstraints);

        jLabel1.setText("Key Store");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        getContentPane().add(jLabel1, gridBagConstraints);

        jLabel2.setText("Certificates");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        getContentPane().add(jLabel2, gridBagConstraints);

        aliasTable.setModel(new javax.swing.table.DefaultTableModel(
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
        jScrollPane2.setViewportView(aliasTable);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 0.5;
        getContentPane().add(jScrollPane2, gridBagConstraints);

        addKeystoreButton.setText("Add Key Store");
        addKeystoreButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addKeystoreButtonActionPerformed(evt);
            }
        });
        jPanel1.add(addKeystoreButton);

        setButton.setText("Activate Selected Alias");
        setButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setButtonActionPerformed(evt);
            }
        });
        jPanel1.add(setButton);

        closeButton.setText("Close");
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });
        jPanel1.add(closeButton);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 6;
        gridBagConstraints.gridwidth = 2;
        getContentPane().add(jPanel1, gridBagConstraints);

        certTextArea.setEditable(false);
        jScrollPane3.setViewportView(certTextArea);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 3;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        getContentPane().add(jScrollPane3, gridBagConstraints);

        jLabel8.setText("Certificate Details");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 2;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        getContentPane().add(jLabel8, gridBagConstraints);

        jLabel9.setText("Active key");
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 4;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        getContentPane().add(jLabel9, gridBagConstraints);

        currentCertTextField.setEditable(false);
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 5;
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = java.awt.GridBagConstraints.WEST;
        getContentPane().add(currentCertTextField, gridBagConstraints);

        setSize(new java.awt.Dimension(600, 400));
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void setButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setButtonActionPerformed
        int ks = keyStoreList.getSelectedIndex();
        int alias = aliasTable.getSelectedRow();
        String fingerprint = "";
        if (ks > -1 && alias>-1) {
            String password;
            if (!_certRepo.isKeyUnlocked(ks, alias)) {
                password = getPassword();
            } else {
                password = null;
            }
            try {
                    _certRepo.unlockKey(ks, alias, password);
                } catch (Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(null, new String[] {"Error accessing key store: ", e.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                }
            Certificate cert = _certRepo.getCertificate(ks, alias);
            try {
                fingerprint = _certRepo.getFingerPrint(cert);
            } catch (KeyStoreException kse) {
                kse.printStackTrace();
                JOptionPane.showMessageDialog(null, new String[] {"Error calculating key fingerprint: ", kse.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                fingerprint = "";
            }
        }
        currentCertTextField.setText(fingerprint);
        _certRepo.setDefaultKey(fingerprint);
    }//GEN-LAST:event_setButtonActionPerformed
            
    private void pkcs11BrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pkcs11BrowseButtonActionPerformed
        File library = chooseFile("Select the native PKCS#11 library", null);
        if (library != null)
            pkcs11LibraryTextField.setText(library.getAbsolutePath());
    }//GEN-LAST:event_pkcs11BrowseButtonActionPerformed
    
    private void pkcs12BrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pkcs12BrowseButtonActionPerformed
        FileFilter filter = new FileFilter() {
            public String getDescription() {
                return "*.p12, *.pfx";
            }
            public boolean accept(File file) {
                String name = file.getName();
                if (file.isDirectory()) return true;
                return name.endsWith(".p12") || name.endsWith(".pfx");
            }
        };
        
        File file = chooseFile("Select a PKCS#12 certificate", filter);
        if (file != null)
            pkcs12FileTextField.setText(file.getAbsolutePath());
    }//GEN-LAST:event_pkcs12BrowseButtonActionPerformed
    
    private File chooseFile(String message, FileFilter filter) {
        JFileChooser jfc = new JFileChooser();
        jfc.setDialogTitle(message);
        jfc.setFileFilter(filter);
        int result = jfc.showOpenDialog(addKeystoreDialog);
        if (result == JFileChooser.APPROVE_OPTION) {
            return jfc.getSelectedFile();
        }
        return null;
    }
    
    private void keystoreOkButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keystoreOkButtonActionPerformed
        try {
            int tab = keystoreTabbedPane.getSelectedIndex();
            if (tab == 0) { // PKCS#12
                String file = pkcs12FileTextField.getText();
                if (file.equals("")) return;
                String kspass = new String(pkcs12PasswordField.getPassword());
                if (kspass.equals(""))
                    kspass = null;
                int ksIndex = _certRepo.loadPKCS12Certificate(file, kspass);
                _keystoreListModel.insertElementAt(_certRepo.getKeyStoreDescription(ksIndex), ksIndex);
            } else if (tab == 1) { //PKCS#11
                String library = pkcs11LibraryTextField.getText();
                if (library.equals("")) return;
                String name = pkcs11NameTextField.getText();
                if (name.equals("")) {
                    name = FilenameUtils.getBaseName(library);
                }
                int slotListIndex = Integer.parseInt(pkcs11SlotListIndexSpinner.getValue().toString());
                int ksIndex = _certRepo.initPKCS11(name, library, slotListIndex);
                if (ksIndex == -1) {
                    throw new RuntimeException("No PKCS11 token available.");
                }
                _keystoreListModel.insertElementAt(_certRepo.getKeyStoreDescription(ksIndex), ksIndex);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, new String[] {"Error loading Key Store: ", e.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        addKeystoreDialog.setVisible(false);
    }//GEN-LAST:event_keystoreOkButtonActionPerformed
    
    private void updateKeystoreList() {
        _keystoreListModel.removeAllElements();
        for (int i=0; i<_certRepo.getKeyStoreCount(); i++) {
            _keystoreListModel.addElement(_certRepo.getKeyStoreDescription(i));
        }
    }
    
    private void keystoreCancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keystoreCancelButtonActionPerformed
        addKeystoreDialog.setVisible(false);
    }//GEN-LAST:event_keystoreCancelButtonActionPerformed
    
    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeButtonActionPerformed
        setVisible(false);
    }//GEN-LAST:event_closeButtonActionPerformed
    
    private void addKeystoreButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addKeystoreButtonActionPerformed
        addKeystoreDialog.setVisible(true);
    }//GEN-LAST:event_addKeystoreButtonActionPerformed
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new CertificateManager().setVisible(true);
            }
        });
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addKeystoreButton;
    private javax.swing.JDialog addKeystoreDialog;
    private javax.swing.JTable aliasTable;
    private javax.swing.JPasswordField askPasswordField;
    private javax.swing.JPanel buttonPanel;
    private javax.swing.JTextArea certTextArea;
    private javax.swing.JButton closeButton;
    private javax.swing.JTextField currentCertTextField;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JList keyStoreList;
    private javax.swing.JButton keystoreCancelButton;
    private javax.swing.JButton keystoreOkButton;
    private javax.swing.JTabbedPane keystoreTabbedPane;
    private javax.swing.JButton pkcs11BrowseButton;
    private javax.swing.JTextField pkcs11LibraryTextField;
    private javax.swing.JTextField pkcs11NameTextField;
    private javax.swing.JPanel pkcs11Panel;
    private javax.swing.JSpinner pkcs11SlotListIndexSpinner;
    private javax.swing.JButton pkcs12BrowseButton;
    private javax.swing.JTextField pkcs12FileTextField;
    private javax.swing.JPanel pkcs12Panel;
    private javax.swing.JPasswordField pkcs12PasswordField;
    private javax.swing.JButton setButton;
    // End of variables declaration//GEN-END:variables
    
    private class AliasTableModel extends AbstractTableModel {
        
        /**
		 * 
		 */
		private static final long serialVersionUID = 7086599198379703765L;
		private int _ks = -1;
        private List<String> _aliases = new ArrayList<String>();
        
        public void setKeystore(int ks) {
            _ks = ks;
            _aliases.clear();
            if (_ks > -1) {
                for (int i=0; i<_certRepo.getAliasCount(ks); i++)
                    _aliases.add(_certRepo.getAliasAt(ks, i));
            }
            fireTableDataChanged();
        }
        
        public String getAlias(int row) {
            return (String) _aliases.get(row);
        }
        
        public int getColumnCount() {
            return 1;
        }

        public String getColumnName(int column) {
            return "Alias";
        }   
        
        public int getRowCount() {
            return _aliases.size();
        }
        
        public Object getValueAt(int row, int col) {
            return _aliases.get(row);
        }
        
    }
    
}
