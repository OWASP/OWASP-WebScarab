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

public class RenderedEdge extends Edge implements Tipped {
    public Color color = null;
    public boolean thick = false;
    public RenderedEdge (Node from, Node to) { super (from, to); }
    public String[] getTip () { return null; }
}
