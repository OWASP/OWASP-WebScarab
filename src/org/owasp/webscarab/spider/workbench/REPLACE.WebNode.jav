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

public class WebNode extends RenderedNode {
    public Link link;
    public int filter;
        // Display mode for outgoing links:
        // NO_LINKS, RETRIEVED_LINKS, WALKED_LINKS, TREE_LINKS, or ALL_LINKS
    public int rendering;

    public WebNode (Link link, int filter, int rendering) {
        this.link = link;
        this.filter = filter;
        this.rendering = rendering;
    }

    public String[] getTip () {
        Page page = link.getPage ();
        return (page != null) ? WebGraph.getTip (page) : WebGraph.getTip (link);
    }
}

