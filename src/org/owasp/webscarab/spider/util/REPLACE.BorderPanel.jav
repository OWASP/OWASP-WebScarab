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

public class BorderPanel extends Panel {

    int left, top, bottom, right;

    public BorderPanel (Insets insets) {
        this.left = insets.left;
        this.top = insets.top;
        this.bottom = insets.bottom;
        this.right = insets.right;
    }

    public BorderPanel (int left, int top, int bottom, int right) {
        this.left = left;
        this.top = top;
        this.bottom = bottom;
        this.right = right;
    }


    public void layout () {
        Dimension d = size ();
        
        int x = left;
        int y = top;
        int w = d.width - left - right;
        int h = d.height - top - bottom;

        Component[] comps = getComponents ();
        for (int i=0; i<comps.length; ++i)
            comps[i].reshape (x, y, w, h);
    }
    
    public Dimension preferredSize () {
        Dimension max = new Dimension (0, 0);
        
        Component[] comps = getComponents ();
        for (int i=0; i<comps.length; ++i) {
            Dimension d = comps[i].preferredSize ();
            max.width = Math.max (d.width, max.width);
            max.height = Math.max (d.height, max.height);
        }
        
        max.width += left+right;
        max.height += top+bottom;
        return max;
    }        

    public Dimension minimumSize () {
        Dimension max = new Dimension (0, 0);
        
        Component[] comps = getComponents ();
        for (int i=0; i<comps.length; ++i) {
            Dimension d = comps[i].minimumSize ();
            max.width = Math.max (d.width, max.width);
            max.height = Math.max (d.height, max.height);
        }
        
        max.width += left+right;
        max.height += top+bottom;
        return max;
    }        

    public static Panel wrap (Component comp, Insets insets) {
        Panel p = new BorderPanel (insets);
        p.add (comp);
        return p;
    }

    public static Panel wrap (Component comp, int left, int top, int bottom, int right) {
        Panel p = new BorderPanel (left, top, bottom, right);
        p.add (comp);
        return p;
    }

    public static Panel wrap (Component comp, int horiz, int vert) {
        Panel p = new BorderPanel (horiz, vert, horiz, vert);
        p.add (comp);
        return p;
    }
    
    public static Panel wrap (Component comp, int all) {
        Panel p = new BorderPanel (all, all, all, all);
        p.add (comp);
        return p;
    }
}

