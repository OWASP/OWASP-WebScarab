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

import java.awt.Color;
import java.awt.Insets;
import java.awt.Rectangle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;

/**
 *
 * @author rdawes
 */
public class RegexSearcher {
    public RegexSearcher(JTextComponent comp, Color matchColor, Color selectionColor) {
        this.comp = comp;
        this.matchPainter = new DefaultHighlighter.DefaultHighlightPainter(matchColor);
        this.selectionPainter = new DefaultHighlighter.DefaultHighlightPainter(selectionColor);
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
        Matcher m = p.matcher(content);
        while (m.find()) {
            for (int i=(m.groupCount()>0?1:0); i<=m.groupCount(); i++) {
                try {
                    highlighter.addHighlight(m.start(i), m.end(i), matchPainter);
                } catch (BadLocationException e) {}
            }
        }
    }
    
    public int previousMatch() {
        Highlighter highlighter = comp.getHighlighter();
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        Highlighter.Highlight last = null, previous = null, current = null;
        
        for (int i = 0; i < highlights.length; i++) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == matchPainter) {
                if (last == null || h.getStartOffset() > last.getStartOffset())
                    last = h;
                if (h.getStartOffset() < pos) {
                    if (previous == null) {
                        previous = h;
                    } else if (previous.getStartOffset() < h.getStartOffset()) {
                        previous = h;
                    }
                }
            } else if (h.getPainter() == selectionPainter) {
                current = h;
            }
        }
        
        if (previous == null)
            previous = last;
        if (previous == null)
            previous = current;
        
        if (previous == null) {
            pos = -1;
        } else {
            if (previous != current) 
                try {
                    if (current != null) {
                        highlighter.removeHighlight(current);
                        highlighter.addHighlight(current.getStartOffset(), current.getEndOffset(), matchPainter);
                    }
                    highlighter.removeHighlight(previous);
                    highlighter.addHighlight(previous.getStartOffset(), previous.getEndOffset(), selectionPainter);
                    center(previous);
                } catch (BadLocationException ble) {
                    // impossible
                }
            pos = previous.getStartOffset();
        }
        return pos;
    }
    
    public int nextMatch() {
        Highlighter highlighter = comp.getHighlighter();
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        Highlighter.Highlight first = null, next = null, current = null;
        
        for (int i = 0; i < highlights.length; i++) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == matchPainter) {
                if (first == null || h.getStartOffset() < first.getStartOffset())
                    first = h;
                if (h.getStartOffset() > pos) {
                    if (next == null) {
                        next = h;
                    } else if (next.getStartOffset() > h.getStartOffset()) {
                        next = h;
                    }
                }
            } else if (h.getPainter() == selectionPainter) {
                current = h;
            }
        }
        
        if (next == null)
            next = first;
        if (next == null)
            next = current;
        
        if (next == null) {
            pos = -1;
        } else {
            if (next != current) 
                try {
                    if (current != null) {
                        highlighter.removeHighlight(current);
                        highlighter.addHighlight(current.getStartOffset(), current.getEndOffset(), matchPainter);
                    }
                    highlighter.removeHighlight(next);
                    highlighter.addHighlight(next.getStartOffset(), next.getEndOffset(), selectionPainter);
                    center(next);
                } catch (BadLocationException ble) {
                    // impossible
                }
            pos = next.getStartOffset();
        }
        return pos;
    }

    private void center(Highlighter.Highlight match) throws BadLocationException {
        Rectangle r = comp.modelToView(match.getStartOffset());
        if (r == null)
        	return;
        r.add(comp.modelToView(match.getEndOffset()));
        if (! comp.getVisibleRect().contains(r))
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

    private JTextComponent comp;
    
    private Highlighter.HighlightPainter matchPainter, selectionPainter;
    
    private int pos = -1;
    
}
