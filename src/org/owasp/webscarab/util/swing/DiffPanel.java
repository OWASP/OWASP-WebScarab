/**
 *
 */
package org.owasp.webscarab.util.swing;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Event;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Iterator;
import java.util.List;
import java.util.prefs.Preferences;

import javax.swing.AbstractAction;
import javax.swing.InputMap;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.KeyStroke;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Document;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import org.owasp.webscarab.util.Diff;
import org.owasp.webscarab.util.Diff.Edit;

/**
 * @author rdawes
 *
 */
public class DiffPanel extends JPanel {
    
    private static final long serialVersionUID = 1604132435765855634L;
    
    public static final String SIDE_BY_SIDE = "SIDEBYSIDE";
    
    public static final String COMBINED = "COMBINED";
    
    private static final NoWrapEditorKit noWrapEditorKit = new NoWrapEditorKit();
    
    private String displayLayout = "";
    
    private JTextPane srcTextPane = null;
    
    private Document srcDoc = null;
    
    private JTextPane dstTextPane = null;
    
    private Document dstDoc = null;
    
    private JTextPane combinedTextPane = null;
    
    private Document combinedDoc = null;
    
    private CharSequence src = null, dst = null;
    
    private List edits = null;
    
    private Color changedColor, addedColor, deletedColor;
    
    private SimpleAttributeSet unchanged, changed, added, deleted;
    
    private CardLayout layout;
    
    private JPanel combinedPanel;
    
    private JPanel bothPanel;
    
    public DiffPanel() {
        this(SIDE_BY_SIDE);
    }
    
    public DiffPanel(String displayLayout) {
        super();
        getPreferences();
        createAttributes();
        createComponents();
        addKeyMappings();
        setDisplayLayout(displayLayout);
    }
    
    private void getPreferences() {
        Preferences prefs = Preferences.userNodeForPackage(getClass());
        if (changedColor == null) {
            int colorSpec = prefs.getInt("changed", Color.YELLOW.getRGB());
            changedColor = new Color(colorSpec);
        }
        if (addedColor == null) {
            int colorSpec = prefs.getInt("added", Color.GREEN.getRGB());
            addedColor = new Color(colorSpec);
        }
        if (deletedColor == null) {
            int colorSpec = prefs.getInt("deleted", Color.PINK.getRGB());
            deletedColor = new Color(colorSpec);
        }
    }
    
    private void addKeyMappings() {
        getActionMap().put("TOGGLELAYOUT", new AbstractAction() {
            private static final long serialVersionUID = 1558804946998494321L;
            
            public void actionPerformed(ActionEvent event) {
                layout.next(DiffPanel.this);
                DiffPanel.this.requestFocusInWindow();
            }
        });
        InputMap inputMap = getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_L, Event.CTRL_MASK),
                "TOGGLELAYOUT");
    }
    
    private void createAttributes() {
        unchanged = new SimpleAttributeSet();
        changed = new SimpleAttributeSet();
        changed.addAttribute(StyleConstants.Background, changedColor);
        added = new SimpleAttributeSet();
        added.addAttribute(StyleConstants.Background, addedColor);
        deleted = new SimpleAttributeSet();
        deleted.addAttribute(StyleConstants.Background, deletedColor);
    }
    
    private void createComponents() {
        layout = new CardLayout();
        setLayout(layout);
        combinedPanel = new JPanel(new BorderLayout());
        combinedTextPane = new JTextPane();
        combinedTextPane.setEditorKit(noWrapEditorKit);
        combinedTextPane.setFont(new java.awt.Font("Monospaced", 0, 12));
        combinedTextPane.setEditable(false);
        combinedPanel.add(new JScrollPane(combinedTextPane));
        
        srcTextPane = new JTextPane();
        srcTextPane.setEditorKit(noWrapEditorKit);
        srcTextPane.setFont(new java.awt.Font("Monospaced", 0, 12));
        srcTextPane.setEditable(false);
        dstTextPane = new JTextPane();
        dstTextPane.setEditorKit(noWrapEditorKit);
        dstTextPane.setFont(new java.awt.Font("Monospaced", 0, 12));
        dstTextPane.setEditable(false);
        JScrollPane srcScrollPane = new JScrollPane(srcTextPane);
        srcScrollPane
                .setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        srcScrollPane
                .setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        JScrollPane dstScrollPane = new JScrollPane(dstTextPane);
        dstScrollPane
                .setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        dstScrollPane
                .setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        JScrollBar horizontalScrollBar = new JScrollBar(JScrollBar.HORIZONTAL);
        JScrollBar verticalScrollBar = new JScrollBar(JScrollBar.VERTICAL);
        srcScrollPane.getHorizontalScrollBar().setModel(
                horizontalScrollBar.getModel());
        srcScrollPane.getVerticalScrollBar().setModel(
                verticalScrollBar.getModel());
        dstScrollPane.getHorizontalScrollBar().setModel(
                horizontalScrollBar.getModel());
        dstScrollPane.getVerticalScrollBar().setModel(
                verticalScrollBar.getModel());
        JPanel panel = new JPanel(new GridLayout(1, 2));
        panel.add(srcScrollPane);
        panel.add(dstScrollPane);
        bothPanel = new JPanel(new BorderLayout());
        bothPanel.add(panel, BorderLayout.CENTER);
        bothPanel.add(horizontalScrollBar, BorderLayout.SOUTH);
        bothPanel.add(verticalScrollBar, BorderLayout.EAST);
        
        this.add(COMBINED, combinedPanel);
        this.add(SIDE_BY_SIDE, bothPanel);
    }
    
    public void setDisplayLayout(String displayLayout) {
        if (!displayLayout.equals(this.displayLayout)) {
            this.displayLayout = displayLayout;
            layout.show(this, displayLayout);
        }
    }
    
    public String getDisplayLayout() {
        return displayLayout;
    }
    
    public void clear() {
        combinedTextPane.setText("");
        srcTextPane.setText("");
        dstTextPane.setText("");
    }
    
    public void showDifferences(CharSequence src, CharSequence dst,
            List edits) {
        this.src = src;
        this.dst = dst;
        this.edits = edits;
        
        deleteDocuments();
        createDocuments();
    }
    
    private void deleteDocuments() {
        combinedDoc = srcDoc = dstDoc = null;
        if (combinedTextPane != null)
            combinedTextPane.setText("");
        if (srcTextPane != null)
            srcTextPane.setText("");
        if (dstTextPane != null)
            dstTextPane.setText("");
    }
    
    private void createDocuments() {
        combinedDoc = new DefaultStyledDocument();
        srcDoc = new DefaultStyledDocument();
        dstDoc = new DefaultStyledDocument();
        Iterator it = edits.iterator();
        int srcLast = 0;
        int dstLast = 0;
        try {
            while (it.hasNext()) {
                Edit edit = (Edit) it.next();
                if (edit.getSrcLocation() > srcLast) {
                    // catch up common items in between edits
                    String s = src.subSequence(srcLast, edit.getSrcLocation())
                    .toString();
                    combinedDoc.insertString(combinedDoc.getLength(), s,
                            unchanged);
                    srcDoc.insertString(srcDoc.getLength(), s, unchanged);
                }
                if (edit.getDstLocation() > dstLast) {
                    String d = dst.subSequence(dstLast, edit.getDstLocation())
                    .toString();
                    // catch up common items in between edits
                    dstDoc.insertString(dstDoc.getLength(), d, unchanged);
                }
                String s = edit.getSrc().toString();
                String d = edit.getDst().toString();
                if (edit.getSrc().length() > 0 && edit.getDst().length() > 0) {
                    combinedDoc.insertString(combinedDoc.getLength(), s,
                            deleted);
                    combinedDoc.insertString(combinedDoc.getLength(), d, added);
                    srcDoc.insertString(srcDoc.getLength(), s, changed);
                    dstDoc.insertString(dstDoc.getLength(), d, changed);
                    int v = countLines(s) - countLines(d);
                    if (v > 0) {
                        String cr = "";
                        for (int i = 0; i < v; i++)
                            cr = cr + "\n";
                        dstDoc.insertString(dstDoc.getLength(), cr, changed);
                    } else if (v < 0) {
                        v = -v;
                        String cr = "";
                        for (int i = 0; i < v; i++)
                            cr = cr + "\n";
                        srcDoc.insertString(srcDoc.getLength(), cr, changed);
                    }
                } else if (edit.getSrc().length() > 0) {
                    combinedDoc.insertString(combinedDoc.getLength(), s,
                            deleted);
                    srcDoc.insertString(srcDoc.getLength(), s, added);
                    dstDoc.insertString(dstDoc.getLength(), s.replaceAll(
                            "[^\n]", " "), deleted);
                } else if (edit.getDst().length() > 0) {
                    combinedDoc.insertString(combinedDoc.getLength(), d, added);
                    srcDoc.insertString(srcDoc.getLength(), d.replaceAll(
                            "[^\n]", " "), deleted);
                    dstDoc.insertString(dstDoc.getLength(), d, added);
                }
                srcLast = edit.getSrcLocation() + s.length();
                dstLast = edit.getDstLocation() + d.length();
            }
            if (srcLast < src.length()) {
                String s = src.subSequence(srcLast, src.length()).toString();
                combinedDoc.insertString(combinedDoc.getLength(), s, unchanged);
                srcDoc.insertString(srcDoc.getLength(), s, unchanged);
            }
            if (dstLast < dst.length()) {
                String d = dst.subSequence(dstLast, dst.length()).toString();
                dstDoc.insertString(dstDoc.getLength(), d, unchanged);
            }
            combinedTextPane.setDocument(combinedDoc);
            srcTextPane.setDocument(srcDoc);
            dstTextPane.setDocument(dstDoc);
        } catch (BadLocationException ble) {
            combinedTextPane.setText(ble.toString());
        }
    }
    
    private int countLines(String string) {
        int lines = 0;
        int last = -1;
        while ((last = string.indexOf("\n", last + 1)) > -1)
            lines++;
        return lines;
    }
    
    public static void main(String[] args) throws Exception {
        JFrame frame = new JFrame("Diff");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        DiffPanel panel = new DiffPanel(DiffPanel.SIDE_BY_SIDE);
        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(panel, BorderLayout.CENTER);
        frame.setBounds(200, 100, 1000, 700);
        frame.setVisible(true);
        String src = "abc\ndef\nghi\nqrs\nxyz\n";
        String dst = "def\nghi\njkl\nmno\nxyz\nlmn\n";
        if (args.length == 2) {
            BufferedReader reader = new BufferedReader(new FileReader(args[0]));
            String line;
            StringBuffer buff = new StringBuffer();
            while ((line = reader.readLine()) != null)
                buff.append(line).append("\n");
            reader.close();
            src = buff.toString();
            reader = new BufferedReader(new FileReader(args[1]));
            buff = new StringBuffer();
            while ((line = reader.readLine()) != null)
                buff.append(line).append("\n");
            reader.close();
            dst = buff.toString();
        }
        List edits = Diff.getEdits(src, dst, '\n');
        System.out.println("Distance: " + Diff.getDistance(edits));
        edits = Diff.refine(src, dst, edits);
        System.out.println("Distance: " + Diff.getDistance(edits));
        panel.showDifferences(src, dst, edits);
    }
    
}
