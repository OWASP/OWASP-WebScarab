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

import websphinx.Link;
public class LinkViewEvent 
{
    Object source;
    Link link;

    public LinkViewEvent (Object source, Link link) {
        this.source = source;
        this.link = link;
    }

    public Object getSource () { return source; }
    public Link getLink () { return link; }

}
