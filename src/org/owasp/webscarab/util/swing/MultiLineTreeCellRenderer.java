/*
 * MultiLineTreeCellRenderer.java
 *
 * Created on 05 April 2005, 12:40
 */

package org.owasp.webscarab.util.swing;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.font.FontRenderContext;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.font.TextLayout;
import java.awt.Font;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.ColorUIResource;
import javax.swing.tree.TreeCellRenderer;


/**
 * @author Nobuo Tamemasa
 * @version 1.0 11/09/98
 */
public class MultiLineTreeCellRenderer extends JPanel implements TreeCellRenderer {
    protected JLabel       icon;
    protected TreeTextArea text;
    
    public MultiLineTreeCellRenderer() {
        setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
        icon = new JLabel() {
            public void setBackground(Color color) {
                if(color instanceof ColorUIResource)
                    color = null;
                super.setBackground(color);
            }
        };
        add(icon);
        add(Box.createHorizontalStrut(4));
        add(text  = new TreeTextArea());
    }
    
    public Component getTreeCellRendererComponent(JTree tree, Object value,
    boolean isSelected, boolean expanded,
    boolean leaf, int row, boolean hasFocus) {
        String  stringValue = tree.convertValueToText(value, isSelected,
        expanded, leaf, row, hasFocus);
        setEnabled(tree.isEnabled());
        text.setText(stringValue);
        text.setSelect(isSelected);
        text.setFocus(hasFocus);
        if (leaf) {
            icon.setIcon(UIManager.getIcon("Tree.leafIcon"));
        } else if (expanded) {
            icon.setIcon(UIManager.getIcon("Tree.openIcon"));
        } else {
            icon.setIcon(UIManager.getIcon("Tree.closedIcon"));
        }
        return this;
    }
    
    public Dimension getPreferredSize() {
        Dimension iconD = icon.getPreferredSize();
        Dimension textD = text.getPreferredSize();
        int height = iconD.height < textD.height ?
        textD.height : iconD.height;
        return new Dimension(iconD.width + textD.width, height);
    }
    
    public void setBackground(Color color) {
        if (color instanceof ColorUIResource)
            color = null;
        super.setBackground(color);
    }
    
    class TreeTextArea extends JTextArea {
        Dimension preferredSize;
        
        TreeTextArea() {
            setLineWrap(true);
            setWrapStyleWord(true);
            setOpaque(true);
        }
        
        public void setBackground(Color color) {
            if(color instanceof ColorUIResource)
                color = null;
            super.setBackground(color);
        }
        
        public void setPreferredSize(Dimension d) {
            if (d != null) {
                preferredSize = d;
            }
        }
        
        public Dimension getPreferredSize() {
            return preferredSize;
        }
        
        public void setText(String str) {
            BufferedImage bufferedImage = new BufferedImage(2, 2, BufferedImage.TYPE_4BYTE_ABGR_PRE);
            Graphics2D g2d = (Graphics2D) (bufferedImage.createGraphics());
            FontRenderContext frc = g2d.getFontRenderContext();
            Font font = getFont();
            
            BufferedReader br = new BufferedReader(new StringReader(str));
            String line;
            double maxWidth = 0, maxHeight = 0;
            int lines = 0;
            try {
                while ((line = br.readLine()) != null) {
                    TextLayout tl = new TextLayout(line, font, frc);
                    maxWidth = Math.max(maxWidth, tl.getBounds().getWidth());
                    maxHeight = Math.max(maxHeight, tl.getBounds().getHeight());
                    lines++;
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            lines = (lines < 1) ? 1: lines;
            int height = (int)(maxHeight * lines);
            int width = (int)(maxWidth + 9); // ?
            setPreferredSize(new Dimension(width, height));
            super.setText(str);
        }
        
        void setSelect(boolean isSelected) {
            Color bColor;
            if (isSelected) {
                bColor = UIManager.getColor("Tree.selectionBackground");
            } else {
                bColor = UIManager.getColor("Tree.textBackground");
            }
            super.setBackground(bColor);
        }
        
        void setFocus(boolean hasFocus) {
            if (hasFocus) {
                Color lineColor = UIManager.getColor("Tree.selectionBorderColor");
                setBorder(BorderFactory.createLineBorder(lineColor));
            } else {
                setBorder(BorderFactory.createEmptyBorder(1,1,1,1));
            }
        }
    }
}