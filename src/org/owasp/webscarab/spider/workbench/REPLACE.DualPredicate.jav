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

public class DualPredicate implements LinkPredicate, PagePredicate {
    Object positive, negative;

    public DualPredicate (Object positive, Object negative) {
        this.positive = positive;
        this.negative = negative;
    }
    public boolean equals (Object object) {
        if (! (object instanceof DualPredicate))
            return false;
        DualPredicate p = (DualPredicate)object;
        return p.positive.equals (positive) && p.negative.equals (negative);
    }    

    public Object getPositivePredicate () {
        return positive;
    }

    public Object getNegativePredicate () {
        return negative;
    }

    public void connected (Crawler crawler) {
        if (positive instanceof LinkPredicate)
            ((LinkPredicate)positive).connected (crawler);
        else if (positive instanceof PagePredicate)
            ((LinkPredicate)positive).connected (crawler);

        if (negative instanceof LinkPredicate)
            ((LinkPredicate)negative).connected (crawler);
        else if (negative instanceof PagePredicate)
            ((LinkPredicate)negative).connected (crawler);
    }

    public void disconnected (Crawler crawler) {
        if (positive instanceof LinkPredicate)
            ((LinkPredicate)positive).disconnected (crawler);
        else if (positive instanceof PagePredicate)
            ((LinkPredicate)positive).disconnected (crawler);

        if (negative instanceof LinkPredicate)
            ((LinkPredicate)negative).disconnected (crawler);
        else if (negative instanceof PagePredicate)
            ((LinkPredicate)negative).disconnected (crawler);
    }
    
    public boolean shouldVisit (Link link) {
        return ((LinkPredicate)positive).shouldVisit (link) 
            && !((LinkPredicate)negative).shouldVisit (link);
    }
    public boolean shouldActOn (Page page) {
        return ((PagePredicate)positive).shouldActOn (page)
            && !((PagePredicate)negative).shouldActOn (page);
    }
}
