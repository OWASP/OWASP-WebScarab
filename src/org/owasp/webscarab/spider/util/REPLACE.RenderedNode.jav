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

// Daniel Tunkelang's graph-drawing packages
import graph.*; 
import gd.*;

import java.awt.*;

public class RenderedNode extends Node implements Tipped {
    public Color color = null;
    public double scale = 1.0;
    public Image icon = null;

    public int screenX; // node's coordinates scaled 
    public int screenY; // and translated to the GraphLayout panel
    
    public RenderedNode () { }
    public String[] getTip () {
        String[] result = new String[1];
        result[0] = name;
        return result;
    }
}

