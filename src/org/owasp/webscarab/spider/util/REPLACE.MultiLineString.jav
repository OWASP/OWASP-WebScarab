/*
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University 
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software 
 * Foundation, version 2.
 *
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.spider.util;

import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Label;
import java.util.StringTokenizer;

// FIX: convert to RichString which supports font and color runs

public class MultiLineString {

    String[] lines;

    public MultiLineString (String string) {
        StringTokenizer tok = new StringTokenizer (string, "\n");
        lines = new String[tok.countTokens ()];
        for (int i=0; i<lines.length; ++i)
            lines[i] = tok.nextToken ();
    }

    public MultiLineString (String[] lines) {
        this.lines = lines;
    }

    public int countLines () {
        return lines.length;
    }

    public String getLineAt (int i) {
        return lines[i];
    }

    public int getWidth (FontMetrics fm) {
        int w = 0;
        for (int i=0; i<lines.length; ++i)
            w = Math.max (w, fm.stringWidth (lines[i]));
        return w;
    }

    public int getHeight (FontMetrics fm) {
        return fm.getHeight() * lines.length;
    }

    public void draw (Graphics g, int x, int y, int alignment) {
        FontMetrics fm = g.getFontMetrics ();
        
        y += fm.getAscent ();
        
        int width = alignment != Label.LEFT
            ? getWidth (fm)
            : 0; // don't need it if alignment is LEFT
        
        for (int i=0; i<lines.length; ++i) {
            int x1 = x;
            switch (alignment) {
                case Label.LEFT:
                    break;
                case Label.RIGHT:
                    x += width - fm.stringWidth (lines[i]);
                    break;
                case Label.CENTER:
                    x += (width - fm.stringWidth (lines[i]))/2;
                    break;
            }
                
            g.drawString (lines[i], x, y);
            y += fm.getHeight ();
        }
    }

}
