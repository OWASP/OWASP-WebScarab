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

import java.util.HashMap;
import java.awt.Color;

public abstract class Colors {

    static HashMap colors = new HashMap ();
    static {
        colors.put ("black", Color.black);
        colors.put ("blue", Color.blue);
        colors.put ("cyan", Color.cyan);
        colors.put ("darkGray", Color.darkGray);
        colors.put ("gray", Color.gray);
        colors.put ("green", Color.green);
        colors.put ("lightGray", Color.lightGray);
        colors.put ("magenta", Color.magenta);
        colors.put ("orange", Color.orange);
        colors.put ("pink", Color.pink);
        colors.put ("red", Color.red);
        colors.put ("white", Color.white);
        colors.put ("yellow", Color.yellow);
    }

    public static Color parseColor (String name) {
        if (name == null)
            return null;

        Color c = (Color)colors.get (name);

        if (c != null)
            return c;
        else if (name.startsWith ("#") && name.length() == 7) {
            c = new Color (Integer.parseInt(name.substring (1, 3), 16),
                              Integer.parseInt(name.substring (3, 5), 16),
                              Integer.parseInt(name.substring (5, 7), 16));
            colors.put (name, c);
            return c;
        }
        else
            return null; // I give up
    }

}
