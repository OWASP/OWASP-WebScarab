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

public class TitlePredicate implements PagePredicate {
    
    Pattern pattern;
    
    public TitlePredicate (Pattern pattern) {
        this.pattern = pattern;
    }

    public boolean equals (Object object) {
        if (! (object instanceof TitlePredicate))
            return false;
        TitlePredicate p = (TitlePredicate)object;
        return p.pattern.equals (pattern);
    }
    
    public Pattern getPattern () { 
        return pattern; 
    }
    
    public void connected (Crawler crawler) {}
    public void disconnected (Crawler crawler) {}
    
    public boolean shouldActOn (Page page) {
        try {
            return pattern.found (page.getTitle());
        } catch (NullPointerException e) {
            return false;
        }
    }
}

