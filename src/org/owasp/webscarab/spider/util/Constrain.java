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

public abstract class Constrain {

    public static void add (Container container, Component comp, Object constraints) {
        container.add (comp);
        GridBagLayout layout = (GridBagLayout)container.getLayout ();
        GridBagConstraints c = (GridBagConstraints)constraints;
        layout.setConstraints (comp, c);
    }        

    public static GridBagConstraints labelLike (int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.weightx = 0;
        c.weighty = 0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.NONE;
        return c;
    }
        
    public static GridBagConstraints labelLike (int x, int y, int w) {
        GridBagConstraints c = labelLike (x, y);
        c.gridwidth = w;
        return c;
    }
        
    public static GridBagConstraints fieldLike (int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        return c;
    }

    public static GridBagConstraints fieldLike (int x, int y, int w) {
        GridBagConstraints c = fieldLike (x, y);
        c.gridwidth = w;
        return c;
    }

    public static GridBagConstraints areaLike (int x, int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.weightx = 1.0;
        c.weighty = 1.0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.BOTH;
        return c;
    }

    public static GridBagConstraints areaLike (int x, int y, int w) {
        GridBagConstraints c = areaLike (x, y);
        c.gridwidth = w;
        return c;
    }

    public static GridBagConstraints rightJustify (GridBagConstraints c) {
        c.anchor = GridBagConstraints.NORTHEAST;
        return c;
    }

    public static GridBagConstraints centered (GridBagConstraints c) {
        c.anchor = GridBagConstraints.CENTER;
        return c;
    }

    public static Panel makeConstrainedPanel () {
        Panel panel = new Panel ();
        panel.setLayout (new GridBagLayout ());
        return panel;        
    }

    public static Panel makeConstrainedPanel (int w, int h) {
        Panel panel = makeConstrainedPanel ();
        
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = h;
        c.gridwidth = w;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.VERTICAL;
        add (panel, new Panel(), c);
        
        c = new GridBagConstraints();
        c.gridx = w;
        c.gridy = 0;
        c.gridheight = h;
        c.weightx = 0.0;
        c.weighty = 1.0;
        c.anchor = GridBagConstraints.NORTHWEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        add (panel, new Panel(), c);
        
        return panel;
    }

}
