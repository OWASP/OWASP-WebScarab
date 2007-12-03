/*
 * RegexSearcher.java
 *
 * Created on 03 March 2006, 12:11
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab.ui.swing.editors;

import java.awt.Insets;
import java.awt.Rectangle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;

/**
 *
 * @author rdawes
 */
public class RegexSearcher {
    public RegexSearcher(JTextComponent comp, Highlighter.HighlightPainter matchPainter, Highlighter.HighlightPainter selectionPainter) {
        this.comp = comp;
        this.matchPainter = matchPainter;
        this.selectionPainter = selectionPainter;
    }
    
    // Highlights all occurrences found of the specified pattern.
    public void search(String pattern, boolean caseSensitive) throws PatternSyntaxException {
        pos = -1;
        Highlighter highlighter = comp.getHighlighter();
        
        // Remove any existing highlights for last search
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        for (int i = 0; i < highlights.length; i++) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == this.matchPainter ||
                    h.getPainter() == this.selectionPainter) {
                highlighter.removeHighlight(h);
            }
        }
        
        if (pattern == null || "".equals(pattern))
            return;
        
        // Look for the pattern we are given - insensitive search
        String content = null;
        try {
            Document d = comp.getDocument();
            content = d.getText(0, d.getLength());
        } catch (BadLocationException e) {
            // Cannot happen
            return;
        }
        
        int flags = Pattern.DOTALL | Pattern.MULTILINE;
        if (!caseSensitive) flags |= Pattern.CASE_INSENSITIVE;
        Pattern p = Pattern.compile(pattern, flags);
        int offset = 0;
        Matcher m = p.matcher(content);
        while (m.find()) {
            for (int i=(m.groupCount()>0?1:0); i<=m.groupCount(); i++) {
                String match = m.group(i);
                try {
                    highlighter.addHighlight(m.start(i), m.end(i), matchPainter);
                } catch (BadLocationException e) {}
            }
        }
    }
    
    public int previousMatch() {
        Highlighter highlighter = comp.getHighlighter();
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        Highlighter.Highlight match = null;
        
        for (int i = highlights.length - 1; i >= 0; i--) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == matchPainter) {
                if (h.getStartOffset() < pos && match == null) {
                    match = h;
                }
            } else if (h.getPainter() == selectionPainter) {
                // remove the painter for the selected item,
                // and replace it with the regular painter
                highlighter.removeHighlight(h);
                try {
                    highlighter.addHighlight(h.getStartOffset(), h.getEndOffset(), matchPainter);
                } catch (BadLocationException ble) {
                    ble.printStackTrace();
                }
            }
        }

        if (match == null) {
            for (int i = highlights.length - 1; i >= 0; i--) {
                Highlighter.Highlight h = highlights[i];
                if (h.getPainter() == matchPainter) {
                    match = h;
                    break;
                }
            }
        }
        
        if (match == null) {
            pos = -1;
        } else {
            try {
                highlighter.removeHighlight(match);
                highlighter.addHighlight(match.getStartOffset(), match.getEndOffset(), selectionPainter);
                center(match);
            } catch (BadLocationException ble) {
                // impossible
            }
            pos = match.getStartOffset();
        }
        return pos;
    }
    
    public int nextMatch() {
        Highlighter highlighter = comp.getHighlighter();
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        Highlighter.Highlight match = null;
        
        for (int i = 0; i < highlights.length; i++) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == matchPainter) {
                if (h.getStartOffset() > pos && match == null) {
                    match = h;
                }
            } else if (h.getPainter() == selectionPainter) {
                // remove the painter for the selected item,
                // and replace it with the regular painter
                highlighter.removeHighlight(h);
                try {
                    highlighter.addHighlight(h.getStartOffset(), h.getEndOffset(), matchPainter);
                } catch (BadLocationException ble) {
                    ble.printStackTrace();
                }
            }
        }

        if (match == null) {
            for (int i = 0; i < highlights.length; i++) {
                Highlighter.Highlight h = highlights[i];
                if (h.getPainter() == matchPainter) {
                    match = h;
                    break;
                }
            }
        }
        
        if (match == null) {
            pos = -1;
        } else {
            try {
                highlighter.removeHighlight(match);
                highlighter.addHighlight(match.getStartOffset(), match.getEndOffset(), selectionPainter);
                center(match);
            } catch (BadLocationException ble) {
                // impossible
            }
            pos = match.getStartOffset();
        }
        return pos;
    }

    private void center(Highlighter.Highlight match) throws BadLocationException {
        Rectangle r = comp.modelToView(match.getStartOffset());
        r.add(comp.modelToView(match.getEndOffset()));
        center(r, false);
    }
    
    private void center(Rectangle r, boolean withInsets) {
        Rectangle visible = comp.getVisibleRect();

        visible.x = r.x - (visible.width - r.width) / 2;
        visible.y = r.y - (visible.height - r.height) / 2;

        Rectangle bounds = comp.getBounds();
        Insets i = withInsets ? new Insets(0, 0, 0, 0) : comp.getInsets();
        bounds.x = i.left;
        bounds.y = i.top;
        bounds.width -= i.left + i.right;
        bounds.height -= i.top + i.bottom;

        if (visible.x < bounds.x)
            visible.x = bounds.x;

        if (visible.x + visible.width > bounds.x + bounds.width)
            visible.x = bounds.x + bounds.width - visible.width;

        if (visible.y < bounds.y)
            visible.y = bounds.y;

        if (visible.y + visible.height > bounds.y + bounds.height)
            visible.y = bounds.y + bounds.height - visible.height;

        comp.scrollRectToVisible(visible);
    }

    protected JTextComponent comp;
    
    protected Highlighter.HighlightPainter matchPainter, selectionPainter;
    
    int pos = -1;
}
