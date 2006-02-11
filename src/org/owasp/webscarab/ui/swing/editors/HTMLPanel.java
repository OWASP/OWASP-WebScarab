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
 * HexEditor.java
 *
 * Created on November 4, 2003, 8:23 AM
 */

package org.owasp.webscarab.ui.swing.editors;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.net.URL;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.event.HyperlinkEvent.EventType;
import javax.swing.text.ChangedCharSetException;

import java.util.logging.Logger;

import org.mozilla.intl.chardet.nsDetector;
import org.mozilla.intl.chardet.nsICharsetDetectionObserver;
import org.mozilla.intl.chardet.nsPSMDetector;

/**
 *
 * @author  rdawes
 */
public class HTMLPanel extends JPanel implements ByteArrayEditor {
    
    private byte[] _data = new byte[0];
    
    private SearchDialog _searchDialog = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private byte[] _bytes = null;
    
    /** Creates new form HexEditor */
    public HTMLPanel() {
        initComponents();
        setName("HTML");
        
        htmlEditorPane.setEditable(false);
        // even though we override getStream in a custom editor pane,
        // if the HTML includes a Frame, the editor Kit creates a new
        // non-custom JEditorPane, which causes problems !!!
        htmlEditorPane.setEditorKit(new MyHTMLEditorKit());
        htmlEditorPane.addHyperlinkListener(new HTMLPanel.LinkToolTipListener());
    }
    
    public String[] getContentTypes() {
        return new String[] { "text/html.*" };
    }
    
    public void setEditable(boolean editable) {
        // We can't edit HTML directly. This panel is just a renderer
        // _editable = editable;
        // htmlEditorPane.setEditable(editable);
        // we could do things like make buttons visible and invisible here
    }

    private String getCharset(String contentType, byte[] bytes) {
        String[] charsets;
        nsDetector det = new nsDetector(nsPSMDetector.ALL);
        
        boolean isAscii = det.isAscii(bytes,bytes.length);
        // DoIt if non-ascii and not done yet.
        if (!isAscii)
            det.DoIt(bytes,bytes.length, false);
        charsets = det.getProbableCharsets();
        det.DataEnd();
        
        if (isAscii) return "ASCII";
        if (charsets.length == 0) return null;
        if (charsets.length == 1 && charsets[0].equals("nomatch")) return null;
        
        return charsets[0];
    }

    public void setBytes(String contentType, byte[] bytes) {
        _bytes = bytes;
        // htmlEditorPane.getDocument().putProperty("base","");
        if (bytes != null) {
            String charset = null;
            if (contentType.indexOf("charset") == -1) {
                charset = getCharset(contentType, bytes);
                contentType = contentType + "; charset="+charset;
            } else {
                charset = contentType.substring(contentType.indexOf("charset=")+8);
            }
            htmlEditorPane.setContentType(contentType);
            // FIXME: may need to reset style sheets, etc here. Not sure how to do that, though
            // Maybe this will work?
            htmlEditorPane.setDocument(JEditorPane.createEditorKitForContentType("text/html").createDefaultDocument());
            htmlEditorPane.putClientProperty("IgnoreCharsetDirective", Boolean.TRUE);
            htmlEditorPane.getDocument().putProperty("IgnoreCharsetDirective", Boolean.TRUE);
            
            try {
                if (charset != null) {
                    htmlEditorPane.setText(new String(bytes, charset));
                } else {
                    htmlEditorPane.setText(new String(bytes));
                }
            } catch (Exception e) {
                _logger.warning("Error setting HTML text: " + e);
                e.printStackTrace();
            }
        } else {
            htmlEditorPane.setText("");
        }
        htmlEditorPane.setCaretPosition(0);
    }
    
    public boolean isModified() {
        return false;
    }
    
    public byte[] getBytes() {
        return _bytes;
    }
    
    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc=" Generated Code ">//GEN-BEGIN:initComponents
    private void initComponents() {
        java.awt.GridBagConstraints gridBagConstraints;

        htmlScrollPane = new javax.swing.JScrollPane();
        htmlEditorPane = new NoNetEditorPane();

        setLayout(new java.awt.GridBagLayout());

        setMinimumSize(new java.awt.Dimension(400, 20));
        setPreferredSize(new java.awt.Dimension(400, 20));
        htmlScrollPane.setViewportView(htmlEditorPane);

        gridBagConstraints = new java.awt.GridBagConstraints();
        gridBagConstraints.gridwidth = java.awt.GridBagConstraints.REMAINDER;
        gridBagConstraints.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints.weightx = 1.0;
        gridBagConstraints.weighty = 1.0;
        add(htmlScrollPane, gridBagConstraints);

    }
    // </editor-fold>//GEN-END:initComponents
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JEditorPane htmlEditorPane;
    private javax.swing.JScrollPane htmlScrollPane;
    // End of variables declaration//GEN-END:variables
    
    private class NoNetEditorPane extends JEditorPane {
        protected InputStream getStream(URL page) throws IOException {
            _logger.info("Rejecting request for " + page);
            throw new IOException("We do not support network traffic");
        }
    }
    
    public class LinkToolTipListener implements HyperlinkListener {
        public LinkToolTipListener() {
        }
        public void hyperlinkUpdate(HyperlinkEvent he) {
            EventType type = he.getEventType();
            if (type == EventType.ENTERED) {
                JEditorPane jep = (JEditorPane) he.getSource();
                URL url = he.getURL();
                if (url != null) {
                    jep.setToolTipText(url.toString());
                } else {
                    jep.setToolTipText(he.getDescription());
                }
            } else if (type == EventType.EXITED) {
                JEditorPane jep = (JEditorPane) he.getSource();
                jep.setToolTipText("");
            }
        }
    }
    
    
}

