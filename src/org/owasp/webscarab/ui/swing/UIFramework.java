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
 *E
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
 * WebScarab.java
 *
 * Created on July 13, 2003, 7:11 PM
 */

package org.owasp.webscarab.ui.swing;

import java.awt.BorderLayout;
import java.awt.Rectangle;

import java.io.File;
import java.io.IOException;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;

import javax.swing.plaf.TextUI;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.text.Position.Bias;

import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.FrameworkModel;
import org.owasp.webscarab.model.FileSystemStore;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.plugin.CredentialManager;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.FrameworkUI;
import org.owasp.webscarab.util.TempDir;
import org.owasp.webscarab.util.TextFormatter;
import org.owasp.webscarab.util.swing.DocumentHandler;
import org.owasp.webscarab.util.swing.HeapMonitor;
import org.owasp.webscarab.util.swing.SwingWorker;

import javax.help.HelpSet;
import javax.help.HelpBroker;
import javax.help.CSH;
import java.net.URL;
import java.net.MalformedURLException;

/**
 *
 * @author  rdawes
 */
public class UIFramework extends JFrame implements FrameworkUI {
    
    private Framework _framework;
    private FrameworkModel _model;
    private ArrayList _plugins;
    
    private CookieJarViewer _cookieJarViewer;
    private CertificateManager _certificateManager;
    private SummaryPanel _summaryPanel;
    
    private TranscoderFrame _transcoder = null;
    private ScriptManagerFrame _scriptManagerFrame = null;
    private CredentialManagerFrame _credentialManagerFrame = null;
    private CredentialRequestDialog _credentialRequestDialog = null;
    
    private Logger _logger = Logger.getLogger("org.owasp.webscarab");
    
    private DocumentHandler _dh;
    
    // we use this to wait on the exit of the UI
    private Object _exit = new Object();
    
    private File _tempDir = null;
    
    /** Creates new form WebScarab */
    public UIFramework(Framework framework) {
        _framework = framework;
        _model = framework.getModel();
        
        initComponents();
        getContentPane().add(new HeapMonitor(), BorderLayout.SOUTH);
        setPreferredSize();
        
        framework.setUI(this);
        
        _summaryPanel = new SummaryPanel(_model);
        tabbedPane.addTab("Summary", _summaryPanel);
        tabbedPane.addTab("Messages", new JScrollPane(logTextArea));
        
        _cookieJarViewer = new CookieJarViewer(_model);
        _certificateManager = new CertificateManager();
        
        CredentialManager cm = _framework.getCredentialManager();
        _credentialManagerFrame = new CredentialManagerFrame(cm);
        _credentialRequestDialog = new CredentialRequestDialog(this, true, cm);
        cm.setUI(_credentialRequestDialog);
        
        initLogging();
        initEditorViews();
        initHelp();
        
    }
    
    private void initHelp() {
        try {
            URL url = getClass().getResource("/help/jhelpset.hs");
            if (url == null) throw new NullPointerException("The help set could not be found");
            HelpSet helpSet = new HelpSet(null, url);
            HelpBroker helpBroker = helpSet.createHelpBroker();
            contentsMenuItem.addActionListener(new CSH.DisplayHelpFromSource(helpBroker));
            helpBroker.enableHelpKey(getRootPane(), "about", helpSet);        // for F1
        } catch (Throwable e) {
            final String[] message;
            if (e instanceof NullPointerException) {
                message = new String[] { "Help set not found" };
            } else if (e instanceof NoClassDefFoundError) {
                message = new String[] {"The JavaHelp libraries could not be found", "Please add jhall.jar to the extension directory of your Java Runtime environment"};
            } else {
                message = new String[] { "Unknown error: ",e.getClass().getName(), e.getMessage()};
            }
            for (int i=0; i<message.length; i++) {
                System.err.println(message[i]);
            }
            contentsMenuItem.addActionListener(new AbstractAction() {
                public void actionPerformed(ActionEvent evt) {
                    JOptionPane.showMessageDialog(UIFramework.this, message, "Help is not available", JOptionPane.ERROR_MESSAGE);
                }
            });
        }
    }
    
    public void run() {
        createTemporarySession();
        synchronized(_exit) {
            try {
                _exit.wait();
            } catch (InterruptedException ie) {
                _logger.info("Interrupted waiting for exit: " + ie);
            }
        }
    }
    
    private void deleteTempdir() {
        if (_tempDir != null) {
            TempDir.recursiveDelete(_tempDir);
            _tempDir = null;
        }
    }
    
    public void initEditorViews() {
        String wrap = Preferences.getPreference("TextPanel.wrap", "false");
        if (wrap != null && wrap.equals("true")) wrapTextCheckBoxMenuItem.setSelected(true);
    }
    
    private void initLogging() {
        _dh = new DocumentHandler(20480); // limit it to 20kB
        _dh.setFormatter(new TextFormatter());
        _logger.addHandler(_dh);
        
        final Document doc = _dh.getDocument();
        logTextArea.setDocument(doc);
        doc.addDocumentListener(new TextScroller(logTextArea));
        
        String level = Preferences.getPreference("UI.logLevel","INFO");
        if (level.equals("SEVERE")) {
            severeLogRadioButtonMenuItem.setSelected(true);
        } else if (level.equals("INFO")) {
            infoLogRadioButtonMenuItem.setSelected(true);
        } else if (level.equals("FINE")) {
            fineLogRadioButtonMenuItem.setSelected(true);
        } else if (level.equals("FINER")) {
            finerLogRadioButtonMenuItem.setSelected(true);
        } else if (level.equals("FINEST")) {
            finestLogRadioButtonMenuItem.setSelected(true);
        }
    }
    
    private void setPreferredSize() {
        try {
            int xpos = Integer.parseInt(Preferences.getPreference("WebScarab.position.x").trim());
            int ypos = Integer.parseInt(Preferences.getPreference("WebScarab.position.y").trim());
            int width = Integer.parseInt(Preferences.getPreference("WebScarab.size.x").trim());
            int height = Integer.parseInt(Preferences.getPreference("WebScarab.size.y").trim());
            setBounds(xpos,ypos,width,height);
        } catch (NumberFormatException nfe) {
            setSize(800,600);
            setExtendedState(MAXIMIZED_BOTH);
        } catch (NullPointerException npe) {
            setSize(800,600);
            setExtendedState(MAXIMIZED_BOTH);
        }
    }
    
    public void addPlugin(final SwingPluginUI plugin) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                JPanel panel = plugin.getPanel();
                if (panel != null) {
                    tabbedPane.addTab(plugin.getPluginName(), panel);
                }
                _summaryPanel.addUrlActions(plugin.getUrlActions());
                _summaryPanel.addUrlColumns(plugin.getUrlColumns());
                _summaryPanel.addConversationActions(plugin.getConversationActions());
                _summaryPanel.addConversationColumns(plugin.getConversationColumns());
            }
        });
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        logLevelButtonGroup = new javax.swing.ButtonGroup();
        logTextArea = new javax.swing.JTextArea();
        tabbedPane = new javax.swing.JTabbedPane();
        mainMenuBar = new javax.swing.JMenuBar();
        fileMenu = new javax.swing.JMenu();
        newMenuItem = new javax.swing.JMenuItem();
        openMenuItem = new javax.swing.JMenuItem();
        saveMenuItem = new javax.swing.JMenuItem();
        exitMenuItem = new javax.swing.JMenuItem();
        viewMenu = new javax.swing.JMenu();
        editorMenu = new javax.swing.JMenu();
        wrapTextCheckBoxMenuItem = new javax.swing.JCheckBoxMenuItem();
        toolsMenu = new javax.swing.JMenu();
        proxyMenuItem = new javax.swing.JMenuItem();
        credentialsMenuItem = new javax.swing.JMenuItem();
        certsMenuItem = new javax.swing.JMenuItem();
        cookieJarMenuItem = new javax.swing.JMenuItem();
        transcoderMenuItem = new javax.swing.JMenuItem();
        scriptMenuItem = new javax.swing.JMenuItem();
        restartMenuItem = new javax.swing.JMenuItem();
        liteMenuItem = new javax.swing.JCheckBoxMenuItem();
        helpMenu = new javax.swing.JMenu();
        contentsMenuItem = new javax.swing.JMenuItem();
        logMenu = new javax.swing.JMenu();
        severeLogRadioButtonMenuItem = new javax.swing.JRadioButtonMenuItem();
        infoLogRadioButtonMenuItem = new javax.swing.JRadioButtonMenuItem();
        fineLogRadioButtonMenuItem = new javax.swing.JRadioButtonMenuItem();
        finerLogRadioButtonMenuItem = new javax.swing.JRadioButtonMenuItem();
        finestLogRadioButtonMenuItem = new javax.swing.JRadioButtonMenuItem();
        aboutMenuItem = new javax.swing.JMenuItem();

        logTextArea.setBackground(new java.awt.Color(204, 204, 204));
        logTextArea.setEditable(false);
        logTextArea.setToolTipText("");

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        setTitle("WebScarab");
        addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentMoved(java.awt.event.ComponentEvent evt) {
                formComponentMoved(evt);
            }
            public void componentResized(java.awt.event.ComponentEvent evt) {
                formComponentResized(evt);
            }
        });
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                UIFramework.this.windowClosing(evt);
            }
        });

        getContentPane().add(tabbedPane, java.awt.BorderLayout.CENTER);

        fileMenu.setMnemonic('F');
        fileMenu.setText("File");
        newMenuItem.setMnemonic('N');
        newMenuItem.setText("New");
        newMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newMenuItemActionPerformed(evt);
            }
        });

        fileMenu.add(newMenuItem);

        openMenuItem.setMnemonic('O');
        openMenuItem.setText("Open");
        openMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openMenuItemActionPerformed(evt);
            }
        });

        fileMenu.add(openMenuItem);

        saveMenuItem.setMnemonic('S');
        saveMenuItem.setText("Save");
        saveMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveMenuItemActionPerformed(evt);
            }
        });

        fileMenu.add(saveMenuItem);

        exitMenuItem.setMnemonic('X');
        exitMenuItem.setText("Exit");
        exitMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitMenuItemActionPerformed(evt);
            }
        });

        fileMenu.add(exitMenuItem);

        mainMenuBar.add(fileMenu);

        viewMenu.setMnemonic('V');
        viewMenu.setText("View");
        editorMenu.setMnemonic('E');
        editorMenu.setText("Content Editors");
        wrapTextCheckBoxMenuItem.setMnemonic('W');
        wrapTextCheckBoxMenuItem.setText("Wrap Text");
        wrapTextCheckBoxMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                wrapTextCheckBoxMenuItemActionPerformed(evt);
            }
        });

        editorMenu.add(wrapTextCheckBoxMenuItem);

        viewMenu.add(editorMenu);

        mainMenuBar.add(viewMenu);

        toolsMenu.setMnemonic('T');
        toolsMenu.setText("Tools");
        proxyMenuItem.setMnemonic('P');
        proxyMenuItem.setText("Proxies");
        proxyMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                proxyMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(proxyMenuItem);

        credentialsMenuItem.setText("Credentials");
        credentialsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                credentialsMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(credentialsMenuItem);

        certsMenuItem.setMnemonic('C');
        certsMenuItem.setText("Certificates");
        certsMenuItem.setToolTipText("Allows configuration of client certificates");
        certsMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                certsMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(certsMenuItem);

        cookieJarMenuItem.setMnemonic('S');
        cookieJarMenuItem.setText("Shared Cookies");
        cookieJarMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cookieJarMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(cookieJarMenuItem);

        transcoderMenuItem.setMnemonic('T');
        transcoderMenuItem.setText("Transcoder");
        transcoderMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                transcoderMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(transcoderMenuItem);

        scriptMenuItem.setText("Script Manager");
        scriptMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                scriptMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(scriptMenuItem);

        restartMenuItem.setText("Restart Plugins");
        restartMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                restartMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(restartMenuItem);

        liteMenuItem.setText("Use Lite interface");
        liteMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                liteMenuItemActionPerformed(evt);
            }
        });

        toolsMenu.add(liteMenuItem);

        mainMenuBar.add(toolsMenu);

        helpMenu.setMnemonic('H');
        helpMenu.setText("Help");
        contentsMenuItem.setText("Contents");
        helpMenu.add(contentsMenuItem);

        logMenu.setMnemonic('L');
        logMenu.setText("Log level");
        logMenu.setToolTipText("Configures the level of logging output displayed");
        logLevelButtonGroup.add(severeLogRadioButtonMenuItem);
        severeLogRadioButtonMenuItem.setText("SEVERE");
        severeLogRadioButtonMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelActionPerformed(evt);
            }
        });

        logMenu.add(severeLogRadioButtonMenuItem);

        logLevelButtonGroup.add(infoLogRadioButtonMenuItem);
        infoLogRadioButtonMenuItem.setText("INFO");
        infoLogRadioButtonMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelActionPerformed(evt);
            }
        });

        logMenu.add(infoLogRadioButtonMenuItem);

        logLevelButtonGroup.add(fineLogRadioButtonMenuItem);
        fineLogRadioButtonMenuItem.setText("FINE");
        fineLogRadioButtonMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelActionPerformed(evt);
            }
        });

        logMenu.add(fineLogRadioButtonMenuItem);

        logLevelButtonGroup.add(finerLogRadioButtonMenuItem);
        finerLogRadioButtonMenuItem.setText("FINER");
        finerLogRadioButtonMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelActionPerformed(evt);
            }
        });

        logMenu.add(finerLogRadioButtonMenuItem);

        logLevelButtonGroup.add(finestLogRadioButtonMenuItem);
        finestLogRadioButtonMenuItem.setText("FINEST");
        finestLogRadioButtonMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelActionPerformed(evt);
            }
        });

        logMenu.add(finestLogRadioButtonMenuItem);

        helpMenu.add(logMenu);

        aboutMenuItem.setMnemonic('A');
        aboutMenuItem.setText("About");
        aboutMenuItem.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aboutMenuItemActionPerformed(evt);
            }
        });

        helpMenu.add(aboutMenuItem);

        mainMenuBar.add(helpMenu);

        setJMenuBar(mainMenuBar);

    }// </editor-fold>//GEN-END:initComponents

    private void liteMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_liteMenuItemActionPerformed
        Preferences.setPreference("WebScarab.lite", Boolean.toString(liteMenuItem.isSelected()));
        if (liteMenuItem.isSelected()) {
            JOptionPane.showMessageDialog(this, "Restart WebScarab in order to switch interfaces", "Restart required", JOptionPane.INFORMATION_MESSAGE);
        }
    }//GEN-LAST:event_liteMenuItemActionPerformed

    private void credentialsMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_credentialsMenuItemActionPerformed
        _credentialManagerFrame.setVisible(true);
    }//GEN-LAST:event_credentialsMenuItemActionPerformed
    
    private void restartMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_restartMenuItemActionPerformed
        if (!_framework.isRunning()) return;
        if (!_framework.stopPlugins()) {
            String[] status = _framework.getStatus();
            JOptionPane.showMessageDialog(this, status, "Error - Plugins are busy", JOptionPane.ERROR_MESSAGE);
        }
        _framework.startPlugins();
    }//GEN-LAST:event_restartMenuItemActionPerformed
    
    private void saveMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveMenuItemActionPerformed
        if (_tempDir != null) {
            JFileChooser jfc = new JFileChooser(Preferences.getPreference("WebScarab.DefaultDir"));
            jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            jfc.setDialogTitle("Select a directory to write the session into");
            int returnVal = jfc.showSaveDialog(this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                final File dir = jfc.getSelectedFile();
                if (FileSystemStore.isExistingSession(dir)) {
                    JOptionPane.showMessageDialog(null, new String[] {dir + " already contains a session ", }, "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                } else {
                    new SwingWorker() {
                        public Object construct() {
                            try {
                                closeSession();
                                TempDir.recursiveCopy(_tempDir, dir);
                                TempDir.recursiveDelete(_tempDir);
                                _tempDir = null;
                                _framework.setSession("FileSystem", dir, "");
                                _framework.startPlugins();
                                return null;
                            } catch (StoreException se) {
                                return se;
                            } catch (IOException ioe) {
                                return ioe;
                            }
                        }
                        
                        public void finished() {
                            Object result = getValue();
                            if (result == null) return;
                            if (result instanceof Exception) {
                                Exception e = (Exception) result;
                                JOptionPane.showMessageDialog(null, new String[] {"Error saving Session : ", e.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    }.start();
                }
                Preferences.setPreference("WebScarab.DefaultDir", jfc.getCurrentDirectory().getAbsolutePath());
            }
        } else {
            try {
                if (_framework.isModified()) {
                    boolean running = _framework.isRunning();
                    if (running)
                        _framework.stopPlugins();
                    _framework.saveSessionData();
                    if (running)
                        _framework.startPlugins();
                }
            } catch (StoreException se) {
                JOptionPane.showMessageDialog(null, new String[] {"Error saving Session : ", se.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_saveMenuItemActionPerformed
    
    private void scriptMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_scriptMenuItemActionPerformed
        if (_scriptManagerFrame == null) _scriptManagerFrame = new ScriptManagerFrame(_framework.getScriptManager());
        _scriptManagerFrame.setVisible(true);
    }//GEN-LAST:event_scriptMenuItemActionPerformed
    
    private void wrapTextCheckBoxMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_wrapTextCheckBoxMenuItemActionPerformed
        Preferences.setPreference("TextPanel.wrap", Boolean.toString(wrapTextCheckBoxMenuItem.isSelected()));
    }//GEN-LAST:event_wrapTextCheckBoxMenuItemActionPerformed
    
    private void loadSession(final File sessionDir) {
        new SwingWorker() {
            public Object construct() {
                try {
                    closeSession();
                    _framework.setSession("FileSystem", sessionDir, "");
                    _framework.startPlugins();
                    return null;
                } catch (StoreException se) {
                    return se;
                }
            }
            public void finished() {
                Object result = getValue();
                if (result == null) return;
                if (result instanceof StoreException) {
                    StoreException se = (StoreException) result;
                    JOptionPane.showMessageDialog(null, new String[] {"Error loading Session : ", se.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.start();
    }
    
    private void createTemporarySession() {
        try {
            _tempDir = TempDir.createTempDir("webscarab", ".tmp", null);
        } catch (IOException ioe) {
            _tempDir = null;
            JOptionPane.showMessageDialog(null, new String[] {"Error creating a temporary session : ", ioe.getMessage()}, "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        if (_tempDir != null) {
            loadSession(_tempDir);
        }
    }
    
    private void openExistingSession() {
        JFileChooser jfc = new JFileChooser(Preferences.getPreference("WebScarab.DefaultDir"));
        jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        jfc.setDialogTitle("Choose a directory that contains a previous session");
        int returnVal = jfc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            final File dir = jfc.getSelectedFile();
            if (!FileSystemStore.isExistingSession(dir)) {
                // FIXME to change this to prompt to create it if it does not already exist
                JOptionPane.showMessageDialog(null, new String[] {dir + " does not contain a session ", }, "Error", JOptionPane.ERROR_MESSAGE);
            } else {
                loadSession(dir);
            }
            Preferences.setPreference("WebScarab.DefaultDir", jfc.getCurrentDirectory().getAbsolutePath());
        }
    }
    
    private void openMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openMenuItemActionPerformed
        openExistingSession();
    }//GEN-LAST:event_openMenuItemActionPerformed
    
    private void closeSession() throws StoreException {
        if (_framework.isRunning()) {
            _framework.stopPlugins();
        }
        if (_framework.isModified()) {
            _framework.saveSessionData();
        }
    }
    
    private void createNewSession() {
        JFileChooser jfc = new JFileChooser(Preferences.getPreference("WebScarab.DefaultDir"));
        jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        jfc.setDialogTitle("Select a directory to write the session into");
        int returnVal = jfc.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            final File dir = jfc.getSelectedFile();
            if (FileSystemStore.isExistingSession(dir)) {
                // FIXME to change this to prompt to open it if it already exists
                JOptionPane.showMessageDialog(null, new String[] {dir + " already contains a session ", }, "Error", JOptionPane.ERROR_MESSAGE);
            } else {
                loadSession(dir);
            }
            Preferences.setPreference("WebScarab.defaultDirectory", jfc.getCurrentDirectory().getAbsolutePath());
        }
    }
    
    private void newMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newMenuItemActionPerformed
        createNewSession();
    }//GEN-LAST:event_newMenuItemActionPerformed
    
    private void formComponentResized(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentResized
        if (! isShowing()) return;
        Preferences.getPreferences().setProperty("WebScarab.size.x",Integer.toString(getWidth()));
        Preferences.getPreferences().setProperty("WebScarab.size.y",Integer.toString(getHeight()));
    }//GEN-LAST:event_formComponentResized
    
    private void formComponentMoved(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_formComponentMoved
        if (! isShowing()) return;
        Preferences.getPreferences().setProperty("WebScarab.position.x",Integer.toString(getX()));
        Preferences.getPreferences().setProperty("WebScarab.position.y",Integer.toString(getY()));
    }//GEN-LAST:event_formComponentMoved
    
    private void logLevelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logLevelActionPerformed
        String cmd = evt.getActionCommand().toUpperCase();
        if (cmd.equals("SEVERE")) {
            _dh.setLevel(Level.SEVERE);
        } else if (cmd.equals("INFO")) {
            _dh.setLevel(Level.INFO);
        } else if (cmd.equals("FINE")) {
            _dh.setLevel(Level.FINE);
        } else if (cmd.equals("FINER")) {
            _dh.setLevel(Level.FINER);
        } else if (cmd.equals("FINEST")) {
            _dh.setLevel(Level.FINEST);
        } else {
            System.err.println("Unknown log level: '" + cmd + "'");
            return;
        }
        Preferences.setPreference("UI.logLevel", cmd);
    }//GEN-LAST:event_logLevelActionPerformed
    
    private void certsMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_certsMenuItemActionPerformed
        _certificateManager.setVisible(true);
    }//GEN-LAST:event_certsMenuItemActionPerformed
    
    private void transcoderMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_transcoderMenuItemActionPerformed
        if (_transcoder == null) {
            _transcoder = new TranscoderFrame();
        }
        _transcoder.setVisible(true);
    }//GEN-LAST:event_transcoderMenuItemActionPerformed
    
    private void cookieJarMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cookieJarMenuItemActionPerformed
        _cookieJarViewer.setVisible(true);
        _cookieJarViewer.toFront();
        _cookieJarViewer.requestFocus();
    }//GEN-LAST:event_cookieJarMenuItemActionPerformed
    
    private void proxyMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_proxyMenuItemActionPerformed
        new ProxyConfig(this, _framework).setVisible(true);
    }//GEN-LAST:event_proxyMenuItemActionPerformed
    
    private void exitMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitMenuItemActionPerformed
        exit();
    }//GEN-LAST:event_exitMenuItemActionPerformed
    
    private void aboutMenuItemActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aboutMenuItemActionPerformed
        String[] message = new String[] {
            "OWASP WebScarab - version " + _framework.getVersion(),
                    " - part of the Open Web Application Security Project",
                    "See http://www.owasp.org/software/webscarab.html",
                    "", "Primary Developer : ",
                    "         Rogan Dawes (rogan at dawes.za.net)"
        };
        JOptionPane.showMessageDialog(this, message, "About WebScarab", JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_aboutMenuItemActionPerformed
    
    /** Exit the Application */
    private void windowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_windowClosing
        exit();
    }//GEN-LAST:event_windowClosing
    
    private void exit() {
        if (_framework.isRunning() && !_framework.stopPlugins()) {
            if (_framework.isModified()) {
                String[] status = _framework.getStatus();
                int count = status.length;
                String[] message = new String[count+2];
                System.arraycopy(status, 0, message, 0, count);
                message[count] = "";
                message[count+1] = "Force data save anyway?";
                int choice = JOptionPane.showOptionDialog(this, message, "Error - Plugins are busy", JOptionPane.YES_NO_OPTION, JOptionPane.ERROR_MESSAGE, null, null, null);
                if (choice != JOptionPane.YES_OPTION) return;
            }
        }
        if (_framework.isModified()) {
            try {
                _framework.saveSessionData();
            } catch (Exception e) {
                int choice = JOptionPane.showOptionDialog(this, new String[] {"Error saving session!", e.toString(), "Quit anyway?"}, "Error!", JOptionPane.YES_NO_OPTION, JOptionPane.ERROR_MESSAGE, null, null, null);
                if (choice != JOptionPane.YES_OPTION) return;
            }
        }
        synchronized(_exit) {
            _exit.notify();
        }
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JMenuItem aboutMenuItem;
    private javax.swing.JMenuItem certsMenuItem;
    private javax.swing.JMenuItem contentsMenuItem;
    private javax.swing.JMenuItem cookieJarMenuItem;
    private javax.swing.JMenuItem credentialsMenuItem;
    private javax.swing.JMenu editorMenu;
    private javax.swing.JMenuItem exitMenuItem;
    private javax.swing.JMenu fileMenu;
    private javax.swing.JRadioButtonMenuItem fineLogRadioButtonMenuItem;
    private javax.swing.JRadioButtonMenuItem finerLogRadioButtonMenuItem;
    private javax.swing.JRadioButtonMenuItem finestLogRadioButtonMenuItem;
    private javax.swing.JMenu helpMenu;
    private javax.swing.JRadioButtonMenuItem infoLogRadioButtonMenuItem;
    private javax.swing.JCheckBoxMenuItem liteMenuItem;
    private javax.swing.ButtonGroup logLevelButtonGroup;
    private javax.swing.JMenu logMenu;
    private javax.swing.JTextArea logTextArea;
    private javax.swing.JMenuBar mainMenuBar;
    private javax.swing.JMenuItem newMenuItem;
    private javax.swing.JMenuItem openMenuItem;
    private javax.swing.JMenuItem proxyMenuItem;
    private javax.swing.JMenuItem restartMenuItem;
    private javax.swing.JMenuItem saveMenuItem;
    private javax.swing.JMenuItem scriptMenuItem;
    private javax.swing.JRadioButtonMenuItem severeLogRadioButtonMenuItem;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JMenu toolsMenu;
    private javax.swing.JMenuItem transcoderMenuItem;
    private javax.swing.JMenu viewMenu;
    private javax.swing.JCheckBoxMenuItem wrapTextCheckBoxMenuItem;
    // End of variables declaration//GEN-END:variables
    
    private class TextScroller implements DocumentListener {
        
        private JTextComponent _component;
        private TextUI _mapper;
        
        public TextScroller(JTextComponent component) {
            _component = component;
            _mapper = _component.getUI();
        }
        
        public void removeUpdate(DocumentEvent e) {}
        
        public void changedUpdate(DocumentEvent e) {}
        
        public void insertUpdate(DocumentEvent e) {
            if (_mapper != null) {
                try {
                    Rectangle newLoc = _mapper.modelToView(_component, e.getOffset(), Bias.Forward);
                    adjustVisibility(newLoc);
                } catch (BadLocationException ble) {
                }
            }
        }
        
        private void adjustVisibility(final Rectangle location) {
            if (location != null) {
                if (SwingUtilities.isEventDispatchThread()) {
                    _component.scrollRectToVisible(location);
                } else {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            _component.scrollRectToVisible(location);
                        }
                    });
                }
            }
        }
        
    }
    
}
