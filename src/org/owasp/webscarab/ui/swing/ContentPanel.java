/*
 * ContentPanel.java
 *
 * Created on November 4, 2003, 8:06 AM
 */

package org.owasp.webscarab.ui.swing;

import java.util.ArrayList;
import java.util.Iterator;

import java.awt.Component;

import org.owasp.webscarab.ui.swing.editors.EditorWrapper;
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
    
    private String _contentType = "";
    private boolean _editable = false;
    private boolean _modified = false;
    
    private byte[] _data = null;
    
    private ArrayList _editors = new ArrayList();
    private HexPanel _hexPanel = new HexPanel();
    
    private int _selected = -1;
    private boolean[] _upToDate = new boolean[] {false};
    
    private static int _preferred = -1;
    
    private Object[] _editorClasses = new Object[] {
        "org.owasp.webscarab.ui.swing.editors.SerializedObjectPanel",
        new String[] {"application/x-serialized-object"},
        
        "org.owasp.webscarab.ui.swing.editors.ImagePanel",
        new String[] {"image/.*"},
        
        "org.owasp.webscarab.ui.swing.editors.UrlEncodedPanel",
        new String[] {"application/x-www-form-urlencoded"},
        
        "org.owasp.webscarab.ui.swing.editors.HTMLPanel",
        new String[] {"text/html.*"},
        
        "org.owasp.webscarab.ui.swing.editors.TextPanel",
        new String[] {
            "text/.*", 
            "application/x-javascript", 
            "application/x-www-form-urlencoded"
        },
    };
    
    /** Creates new form ContentPanel */
    public ContentPanel() {
        initComponents();
        viewTabbedPane.getModel().addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                updateData(_selected);
                _preferred = viewTabbedPane.getSelectedIndex();
                updatePanel(viewTabbedPane.getSelectedIndex());
            }
        });
        for (int i=0; i<_editorClasses.length; i+=2) {
            try {
                String name = (String) _editorClasses[i];
                String[] types = (String[]) _editorClasses[i+1];
                EditorWrapper wrapper = new EditorWrapper(name, types);
                _editors.add(wrapper);
            } catch (Exception e) {
                System.err.println("Error instantiating " + _editorClasses[i] + " : " + e);
            }
        }
        
        if (_preferred > -1 && _preferred < viewTabbedPane.getTabCount()) viewTabbedPane.setSelectedIndex(_preferred);
    }
    
    public void setContent(final String type, final byte[] content, final boolean editable) {
        _editable = editable;
        _modified = false;
        if (content == null) {
            _data = null;
        } else {
            _data = new byte[content.length];
            System.arraycopy(content, 0, _data, 0, content.length);
        }
        if (SwingUtilities.isEventDispatchThread()) {
            initPanels(type, content, editable);
        } else {
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    initPanels(type, content, editable);
                }
            });
        }
    }
    
    private void initPanels(String type, byte[] content, boolean editable) {
        if (type == null || !type.equals(_contentType)) {
            _contentType = type;
            addEditors();
            updatePanel(0);
        } else {
            updatePanel(viewTabbedPane.getSelectedIndex());
        }
    }
    
    private void addEditors() {
        viewTabbedPane.removeAll();
        if ((_data != null && _data.length > 0 ) || _editable) {
            if (_contentType != null) {
                Iterator it = _editors.iterator();
                while (it.hasNext()) {
                    EditorWrapper wrapper = (EditorWrapper) it.next();
                    if (wrapper.canEdit(_contentType)) {
                        viewTabbedPane.add(wrapper.getEditorComponent());
                    }
                }
            }
            viewTabbedPane.add(_hexPanel.getName(), _hexPanel);
        }
        _upToDate = new boolean[viewTabbedPane.getTabCount()];
        invalidatePanels();
        invalidate();
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
        org.owasp.webscarab.model.Response response = new org.owasp.webscarab.model.Response();
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
            String filename = "l1/conversations/1-response";
            if (args.length == 1) {
                filename = args[0];
            }
            java.io.FileInputStream fis = new java.io.FileInputStream(filename);
            response.read(fis);
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
            cp.setContent(response.getHeader("Content-Type"), response.getContent(), false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTabbedPane viewTabbedPane;
    // End of variables declaration//GEN-END:variables
    
}
