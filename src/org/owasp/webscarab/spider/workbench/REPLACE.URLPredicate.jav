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

public class URLPredicate implements LinkPredicate, PagePredicate {
    Pattern pattern;
    
    public URLPredicate (Pattern pattern) {
        this.pattern = pattern;
    }
    public boolean equals (Object object) {
        if (! (object instanceof URLPredicate))
            return false;
        URLPredicate p = (URLPredicate)object;
        return p.pattern.equals (pattern);
    }    

    public Pattern getPattern () {
        return pattern;
    }

    public void connected (Crawler crawler) {}
    public void disconnected (Crawler crawler) {}
    
    public boolean shouldVisit (Link link) {
        return pattern.found (link.getURL().toString());
    }
    public boolean shouldActOn (Page page) {
        try {
            return pattern.found (page.getOrigin().getURL().toString());
        } catch (NullPointerException e) {
            return false;
        }
    }
}

