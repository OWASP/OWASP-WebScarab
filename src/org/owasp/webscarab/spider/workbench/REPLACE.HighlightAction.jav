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
package org.owasp.webscarab.spider.workbench;

import websphinx.*;

public class HighlightAction implements Action {
    String color;
    String scale;
    String icon;
    public HighlightAction (String color, String scale, String icon) {
        this.color = color;
        this.scale = scale;
        this.icon = icon;
    }
    
    public boolean equals (Object object) {
        if (! (object instanceof HighlightAction))
            return false;
        HighlightAction a = (HighlightAction)object;
        return same (a.color, color) 
            && same (a.scale, scale)
            && same (a.icon, icon);
    }    

    private boolean same (String s1, String s2) {
        if (s1 == null || s2 == null)
            return s1 == s2;
        else
            return s1.equals (s2);
    }

    public String getColor () {
        return color;
    }
    
    public String getScale () {
        return scale;
    }
    
    public String getIcon () {
        return icon;
    }

    public void connected (Crawler crawler) {}
    public void disconnected (Crawler crawler) {}
    
    public void visit (Page page) {
        if (color != null)
            page.setLabel ("Workbench.color", color);
        if (scale != null)
            page.setLabel ("Workbench.scale", color);
        if (icon != null)
            page.setLabel ("Workbench.icon", color);
    }
}

