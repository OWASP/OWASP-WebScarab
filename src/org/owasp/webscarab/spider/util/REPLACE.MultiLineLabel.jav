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

import java.awt.*;

public class MultiLineLabel extends Canvas {
    private String text;
    private MultiLineString multilabel;
    private int alignment;
    
    private Dimension minSize;  // cached result of getMinimumSize()
    
    public MultiLineLabel (String string) {
        setText (string);
        setAlignment (Label.LEFT);
    }
    
    public MultiLineLabel (String string, int alignment) {
        setText (string);
        setAlignment (alignment);
    }
    
    public String getText () {
        return text;
    }
    public void setText (String string) {
        text = string;
        multilabel = new MultiLineString (string);
        minSize = null;
    }
    
    public int getAlignment () {
        return alignment;
    }
    public void setAlignment (int align) {
        alignment = align;
    }
    
    public void setFont (Font font) {
        super.setFont (font);
        minSize = null;
    }

    public Dimension minimumSize () {
        // FIX: cache this size
        if (minSize == null) {
            FontMetrics fm = getFontMetrics (getFont ());
            minSize = new Dimension (multilabel.getWidth (fm),
                                     multilabel.getHeight (fm));
        }
        return minSize;
    }
    
    public Dimension preferredSize () {
        return minimumSize ();
    }
    
    public synchronized void paint (Graphics g) {
        multilabel.draw (g, 0, 0, alignment);
    }
}

