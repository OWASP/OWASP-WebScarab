/*
 * ContentPanel.java
 *
 * Created on November 4, 2003, 8:06 AM
 */

package org.owasp.webscarab.ui.swing;

import java.util.ArrayList;
import java.util.Iterator;

import java.awt.Component;

import org.owasp.webscarab.ui.swing.editors.ByteArrayEditor;
import org.owasp.webscarab.ui.swing.editors.HexPanel;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;
import javax.swing.SwingUtilities;

// for main()
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

/**
 *
 * @author  rdawes
 */
public class ContentPanel extends javax.swing.JPanel {
    
    private String _contentType = null;
    private boolean _editable = false;
    private boolean _modified = false;
    
    private byte[] _data = null;
    
    private ArrayList _editors = new ArrayList();
    private HexPanel _hexPanel = new HexPanel();
    
    private int _selected = -1;
    private boolean[] _upToDate = new boolean[] {false};
    
    // private ObjectPanel _objectPanel = new ObjectPanel();
    
    private String[] _editorClasses = new String[] {
        "org.owasp.webscarab.ui.swing.editors.SerializedObjectPanel",
        "org.owasp.webscarab.ui.swing.editors.ImagePanel",
        "org.owasp.webscarab.ui.swing.editors.UrlEncodedPanel",
        "org.owasp.webscarab.ui.swing.editors.HTMLPanel",
        "org.owasp.webscarab.ui.swing.editors.TextPanel",
    };
    
    /** Creates new form ContentPanel */
    public ContentPanel() {
        initComponents();
        viewTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                updateData(_selected);
                updatePanel(viewTabbedPane.getSelectedIndex());
            }
        });
        for (int i=0; i<_editorClasses.length; i++) {
            try {
                Object editor = Class.forName(_editorClasses[i]).newInstance();
                if (editor instanceof ByteArrayEditor && editor instanceof Component) {
                    _editors.add(editor);
                } else {
                    System.err.println(_editorClasses[i] + " must implement ByteArrayEditor as well as java.awt.Component");
                }
            } catch (Exception e) {
                System.err.println("Error instantiating " + _editorClasses[i] + " : " + e);
            }
        }
        setEditable(false);
        // FIXME : Strange - this is required to prevent exceptions when setting a 
        // non-null content for the first time :-(
        setContent(null); 
    }
    
    public void setContentType(String type) {
        _contentType = type;
    }
    
    public void setEditable(boolean editable) {
        _editable = editable;
    }
    
    public void setContent(byte[] content) {
        _modified = false;
        if (content == null) {
            _data = null;
        } else {
            _data = new byte[content.length];
            System.arraycopy(content, 0, _data, 0, content.length);
        }
        if (SwingUtilities.isEventDispatchThread()) {
            addEditors();        
            updatePanel(viewTabbedPane.getSelectedIndex());
        } else {
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        addEditors();        
                        updatePanel(viewTabbedPane.getSelectedIndex());
                    }
                });
            } catch (Exception e) {
                System.err.println("Exception in runnable");
                e.printStackTrace();
            }
        }
    }
    
    private void addEditors() {
        viewTabbedPane.removeAll();
        if (_contentType != null) {
            Iterator it = _editors.iterator();
            while (it.hasNext()) {
                ByteArrayEditor editor = (ByteArrayEditor) it.next();
                String[] types = editor.getContentTypes();
                for (int i=0; i<types.length; i++) {
                    if (_contentType.matches(types[i])) {
                        viewTabbedPane.add((Component) editor);
                        continue;
                    }
                }
            }
        }
        if (_data != null || _editable) {
            viewTabbedPane.add(_hexPanel.getName(), _hexPanel);
        }
        _upToDate = new boolean[viewTabbedPane.getTabCount()];
        invalidatePanels();
    }

    public boolean isModified() {
        ByteArrayEditor ed = ((ByteArrayEditor) viewTabbedPane.getSelectedComponent());
        boolean selectedModified = false;
        if (ed != null) {
            selectedModified = ed.isModified();
        }
        return _editable && (_modified || selectedModified);
    }
    
    public byte[] getContent() {
        updateData(_selected);
        return _data;
    }
    
    private void invalidatePanels() {
        for (int i=0; i<_upToDate.length; i++) {
            _upToDate[i] = false;
        }
    }
    
    private void updatePanel(int panel) {
        if (panel<0 || _upToDate.length == 0) {
            return;
        } else if (panel >= _upToDate.length) {
            panel = 0;
        }
        _selected = panel;
        if (!_upToDate[panel]) {
            ByteArrayEditor editor = (ByteArrayEditor) viewTabbedPane.getComponentAt(panel);
            editor.setEditable(_editable);
            editor.setBytes(_data);
            _upToDate[panel] = true;
        }
    }
    
    private void updateData(int panel) {
        if (_editable && panel >= 0) {
            ByteArrayEditor ed = (ByteArrayEditor) viewTabbedPane.getComponentAt(panel);
            if (ed.isModified()) {
                _modified = true;
                _data = ed.getBytes();
                invalidatePanels();
                _upToDate[panel] = true;
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

        viewTabbedPane = new javax.swing.JTabbedPane();

        setLayout(new java.awt.GridBagLayout());

        viewTabbedPane.setMinimumSize(new java.awt.Dimension(200, 50));
        viewTabbedPane.setPreferredSize(new java.awt.Dimension(200, 50));
        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(viewTabbedPane, gridBagConstraints);

    }//GEN-END:initComponents
    
    
    public static void main(String[] args) {
        org.owasp.webscarab.model.Request request = new org.owasp.webscarab.model.Request();
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            /*
            FileInputStream fis = new FileInputStream("/home/rdawes/exodus/HowTo.html");
            byte[] buff = new byte[1024];
            int got = 0;
            while ((got = fis.read(buff)) > 0) {
                baos.write(buff, 0, got);
            }
            content = baos.toByteArray();
             */
            String filename = "/home/rdawes/santam/webscarab/conversations/147-request";
            if (args.length == 1) {
                filename = args[0];
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(filename);
            request.read(fis);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
        
        javax.swing.JFrame top = new javax.swing.JFrame("Content Pane");
        top.getContentPane().setLayout(new java.awt.BorderLayout());
        top.addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                System.exit(0);
            }
        });
        
        javax.swing.JButton button = new javax.swing.JButton("GET");
        final ContentPanel cp = new ContentPanel();
        top.getContentPane().add(cp);
        top.getContentPane().add(button, java.awt.BorderLayout.SOUTH);
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                System.out.println(new String(cp.getContent()));
            }
        });
        top.setBounds(100,100,600,400);
        top.show();
        try {
            // Thread.currentThread().sleep(5000);
            cp.setContentType(request.getHeader("Content-Type"));
            cp.setEditable(true);
            // cp.setContent(null);
            // Thread.currentThread().sleep(5000);
            cp.setContent(request.getContent());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTabbedPane viewTabbedPane;
    // End of variables declaration//GEN-END:variables
    
}
