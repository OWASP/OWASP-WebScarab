/*
 * UrlTreeRenderer.java
 *
 * Created on August 8, 2004, 5:16 PM
 */

package org.owasp.webscarab.ui.swing;

import org.owasp.webscarab.model.HttpUrl;

import java.awt.Component;
import javax.swing.JTree;
import javax.swing.JLabel;
import javax.swing.tree.DefaultTreeCellRenderer;

/**
 *
 * @author  knoppix
 */
public class UrlTreeRenderer extends DefaultTreeCellRenderer {
    
    /** Creates a new instance of UrlTreeRenderer */
    public UrlTreeRenderer() {
    }
    
    public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
        Component comp = super.getTreeCellRendererComponent(tree, value, selected, expanded, leaf, row, hasFocus);
        if (value instanceof HttpUrl && comp instanceof JLabel) {
            JLabel label = (JLabel) comp;
            HttpUrl url = (HttpUrl) value;
            if (url.getParameters() != null) {
                label.setText(url.getParameters());
            } else if (url.getPath().length()>1) {
                String path = url.getPath();
                int pos = path.lastIndexOf("/", path.length()-2);
                label.setText(path.substring(pos+1));
            }
        }
        return comp;
    }
    
}
