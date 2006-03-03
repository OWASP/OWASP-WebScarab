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
    public RegexSearcher(JTextComponent comp, Highlighter.HighlightPainter painter) {
        this.comp = comp;
        this.painter = painter;
    }
    
    // Search for a word and return the offset of the
    // first occurrence. Highlights are added for all
    // occurrences found.
    public int search(String pattern, int start, boolean caseSensitive) throws PatternSyntaxException {
        int firstOffset = -1;
        Highlighter highlighter = comp.getHighlighter();
        
        // Remove any existing highlights for last word
        Highlighter.Highlight[] highlights = highlighter.getHighlights();
        for (int i = 0; i < highlights.length; i++) {
            Highlighter.Highlight h = highlights[i];
            if (h.getPainter() == this.painter) {
                highlighter.removeHighlight(h);
            }
        }
        
        if (pattern == null || pattern.equals("")) {
            return -1;
        }
        
        // Look for the word we are given - insensitive search
        String content = null;
        try {
            Document d = comp.getDocument();
            content = d.getText(0, d.getLength());
        } catch (BadLocationException e) {
            // Cannot happen
            return -1;
        }
        
        int flags = Pattern.DOTALL | Pattern.MULTILINE;
        if (!caseSensitive) flags |= Pattern.CASE_INSENSITIVE;
        Pattern p = Pattern.compile(pattern, flags);
        int offset = 0;
        Matcher m = p.matcher(content);
        while (m.find()) {
            for (int i=(m.groupCount()>0?1:0); i<=m.groupCount(); i++) {
                String match = m.group(i);
                if (firstOffset == -1 && m.start(i)>start) firstOffset = m.start(i);
                try {
                    highlighter.addHighlight(m.start(i), m.end(i), painter);
                } catch (BadLocationException e) {}
            }
        }
        
        return firstOffset;
    }
    
    protected JTextComponent comp;
    
    protected Highlighter.HighlightPainter painter;
    
}
