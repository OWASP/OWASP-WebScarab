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
import websphinx.util.GraphLayout;
import websphinx.util.RenderedEdge;
import websphinx.util.RenderedNode;

public class WebEdge extends RenderedEdge {
    public Link link;

    public WebEdge (Link link, WebNode from, WebNode to) {
        super (from, to);
        this.link = link;
    }
    public String[] getTip () {
        return WebGraph.getTip (link);
    }

}

