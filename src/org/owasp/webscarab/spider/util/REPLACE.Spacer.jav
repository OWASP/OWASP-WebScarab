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

public class Spacer extends Canvas {
    private Dimension d;

    public Spacer (int width, int height) {
        d = new Dimension (width, height);
    }

    public Spacer (Dimension _d) {
        d = new Dimension (_d);
    }

    public Dimension minimumSize () {
        return d;
    }

    public Dimension preferredSize () {
        return d;
    }
}
