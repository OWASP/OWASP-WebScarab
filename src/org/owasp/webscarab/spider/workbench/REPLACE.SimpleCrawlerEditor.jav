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
import java.awt.*;
import websphinx.util.Constrain;

public class SimpleCrawlerEditor extends CrawlerEditor {

    Label actionLabel;
    ActionEditor actionEditor;

    public SimpleCrawlerEditor () {
        super ();

        // remove all the pieces we don't need
        remove (typeLabel);
        remove (typeChoice);
        remove (depthLabel);
        remove (depthField);
        remove (depthLabel2);
        remove (searchOrderChoice);

        // add an action editor
        actionLabel = new Label("Action:");
        actionEditor = new ActionEditor ();
        Constrain.add (this, actionLabel, 
                       Constrain.labelLike (0, 4));
        Constrain.add (this, actionEditor, 
                       Constrain.areaLike (1, 4, 4));
    }

    public void setCrawler (Crawler crawler) {
        super.setCrawler (crawler);
        actionEditor.setAction (crawler.getAction());
    }

    public Crawler getCrawler () {
        crawler.setAction (actionEditor.getAction ());
        return super.getCrawler ();
    }

}
