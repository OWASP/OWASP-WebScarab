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

public class LabelPredicate implements LinkPredicate, PagePredicate {
    String labels;
    boolean orTerms;

    public LabelPredicate (String labels, boolean orTerms) {
        this.labels = labels;
        this.orTerms = orTerms;
    }

    public boolean equals (Object object) {
        if (! (object instanceof LabelPredicate))
            return false;
        LabelPredicate p = (LabelPredicate)object;
        return p.labels.equals (labels)
            && p.orTerms == orTerms;
    }    

    public String getLabels () {
        return labels;
    }

    public boolean getOrTerms () {
        return orTerms;
    }

    public void connected (Crawler crawler) {}
    public void disconnected (Crawler crawler) {}
    
    public boolean shouldVisit (Link link) {
        return orTerms ? link.hasAnyLabels (labels) : link.hasAllLabels (labels);
    }

    public boolean shouldActOn (Page page) {
        return orTerms ? page.hasAnyLabels (labels) : page.hasAllLabels (labels);
    }
}

