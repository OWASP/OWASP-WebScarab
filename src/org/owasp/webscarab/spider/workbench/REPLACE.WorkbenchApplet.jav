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

import java.applet.*;
import java.awt.*;
import java.net.URL;
import websphinx.Crawler;
import websphinx.TagExp;
import websphinx.util.PopupDialog;

public class WorkbenchApplet extends Applet {

    Workbench workbench;

    public Workbench makeWorkbench () {
        String openURL = getParameter ("open");
        String newClassname = getParameter ("new");
        
        try {
            if (openURL != null)
                return new Workbench (new URL (getDocumentBase (), openURL));
            else if (newClassname != null)
                return new Workbench ((Crawler)Class.forName (newClassname).newInstance());
            else
                return new Workbench ();        
        } catch (Exception e) {
            PopupDialog.warn (null, 
                              "Error", 
                              e.toString());
            throw new Error (e.toString());
        }
    }

    public void init () {
        super.init ();

        String targetName = getParameter ("target");
        if (targetName != null)
            Context.setApplet (this, targetName);
        else
            Context.setApplet (this);

        workbench = makeWorkbench ();

        String param;
        if ((param = getParameter ("advanced")) != null)
            workbench.setAdvancedMode (isTrue (param));

        /*
        if ((param = getParameter ("graph")) != null)
            workbench.setGraphVisible (isTrue (param));
            
        if ((param = getParameter ("statistics")) != null)
            workbench.setStatisticsVisible (isTrue (param));
            
        if ((param = getParameter ("log")) != null)
            workbench.setLoggerVisible (isTrue (param));
        */

        Crawler crawler = workbench.getCrawler();

        String action = getParameter ("action");
        if (action != null) {
            String filename = getParameter ("filename");
            String pattern = getParameter ("pattern");
            
            if (action.equalsIgnoreCase ("concatenate"))
                crawler.setAction (new ConcatAction (filename, true));
            else if (action.equalsIgnoreCase ("save"))
                crawler.setAction (new MirrorAction (filename, true));
            else if (action.equalsIgnoreCase ("visualize")) {
                crawler.setAction (null);
                //workbench.setGraphVisible (true);
            }
            else if (action.equalsIgnoreCase ("extract"))
                crawler.setAction (new ExtractAction (new TagExp (pattern), 
                                                  true, filename, false));
            else if (action.equalsIgnoreCase ("none"))
                crawler.setAction (null);
            else
                throw new RuntimeException ("unknown action: " +action);
        }
        
        String urls = getParameter ("urls");
        if (urls != null)
            try {
                crawler.setRootHrefs (urls);
            } catch (java.net.MalformedURLException e) {
                throw new RuntimeException (e.toString());
            }
        
        String domain = getParameter ("domain");
        if (domain != null) {
            if (domain.equalsIgnoreCase ("server"))
                crawler.setDomain (Crawler.SERVER);
            else if (domain.equalsIgnoreCase ("subtree"))
                crawler.setDomain (Crawler.SUBTREE);
            else
                crawler.setDomain (Crawler.WEB);
        }
        
        String type = getParameter ("type");
        if (type != null) {
            if (type.equalsIgnoreCase ("images+hyperlinks"))
                crawler.setLinkType (Crawler.HYPERLINKS_AND_IMAGES);
            else if (type.equalsIgnoreCase ("all"))
                crawler.setLinkType (Crawler.ALL_LINKS);
            else
                crawler.setLinkType (Crawler.WEB);
        }

        String depth = getParameter ("depth");
        if (depth != null)
            crawler.setMaxDepth (Integer.parseInt (depth));

        String dfs = getParameter ("depthfirst");
        if (dfs != null)
            crawler.setDepthFirst (isTrue (dfs));

        workbench.setCrawler (crawler);

        setLayout (new BorderLayout ());
        add ("Center", workbench);
    }

    private static boolean isTrue (String s) {
        return s != null && 
            (s.equalsIgnoreCase ("on") 
             || s.equalsIgnoreCase ("1") 
             || s.equalsIgnoreCase ("yes") 
             || s.equalsIgnoreCase ("true"));
    }
}
