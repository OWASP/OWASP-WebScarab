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

public class ContentPredicate implements LinkPredicate, PagePredicate {
    Pattern pattern;
    boolean overHTML;
    
    public ContentPredicate (Pattern pattern, boolean overHTML) {
        this.pattern = pattern;
        this.overHTML = overHTML;
    }
    public boolean equals (Object object) {
        if (! (object instanceof ContentPredicate))
            return false;
        ContentPredicate p = (ContentPredicate)object;
        return p.pattern.equals (pattern)
            && p.overHTML == overHTML;
    }    

    public Pattern getPattern () {
        return pattern;
    }
    public boolean getOverHTML () {
        return overHTML;
    }

    public void connected (Crawler crawler) {}
    public void disconnected (Crawler crawler) {}
    
    public boolean shouldVisit (Link link) {
        return overHTML ? pattern.found (link) : pattern.found (link.toText());
    }
    public boolean shouldActOn (Page page) {
        return overHTML ? pattern.found (page) : pattern.found (page.toText());
    }
}

