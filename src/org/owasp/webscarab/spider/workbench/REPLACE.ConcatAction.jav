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
import java.io.File;
import java.io.IOException;

public class ConcatAction implements Action, CrawlListener {
    String filename;
    boolean useBrowser;
    String prolog, header, footer, divider, epilog;

    transient File file;
    transient Concatenator concat;

    public ConcatAction (String filename, boolean useBrowser) {
        this.filename = filename;
        this.useBrowser = useBrowser;
    }

    public ConcatAction (String filename, boolean useBrowser,
                         String prolog, String header, String footer, 
                         String divider, String epilog) {
        this (filename, useBrowser);
        this.prolog = prolog;
        this.header = header;
        this.footer = footer;
        this.divider = divider;
        this.epilog = epilog;
    }
    
    public boolean equals (Object object) {
        if (! (object instanceof ConcatAction))
            return false;
        ConcatAction a = (ConcatAction)object;
        return same (a.filename, filename) && a.useBrowser == useBrowser;
    }
    
    private boolean same (String s1, String s2) {
        if (s1 == null || s2 == null)
            return s1 == s2;
        else
            return s1.equals (s2);
    }

    public String getFilename () {
        return filename;
    }

    public boolean getUseBrowser () {
        return useBrowser;
    }

    private transient boolean oldSync;

    public void connected (Crawler crawler) {
        oldSync = crawler.getSynchronous ();
        crawler.setSynchronous (true);
        crawler.addCrawlListener (this);
    }

    public void disconnected (Crawler crawler) {
        crawler.setSynchronous (oldSync);
        crawler.removeCrawlListener (this);
    }
   

    private void showit () {
      Browser browser = Context.getBrowser();
      if (browser != null)
        browser.show (file);
    }

    public synchronized void visit (Page page) {
        try {
            concat.writePage (page);
        } catch (IOException e) {
            throw new RuntimeException (e.toString());
        }
    }

    /**
     * Notify that the crawler started.
     */
    public void started (CrawlEvent event){
        if (concat == null) {
            try {
                file = (filename != null)
                  ? new File (filename)
                  : SecurityPolicy.getPolicy().makeTemporaryFile ("concat", ".html");
                concat = new Concatenator (file.toString());
                
                if (prolog != null)
                    concat.setProlog (prolog);
                if (header != null)
                    concat.setPageHeader (header);
                if (footer != null)
                    concat.setPageFooter (footer);
                if (divider != null)
                    concat.setDivider (divider);
                if (epilog != null)
                    concat.setEpilog (epilog);
            } catch (IOException e) {
                System.err.println (e); // FIX: use GUI when available
            }
        }
    }

    /**
     * Notify that the crawler ran out of links to crawl
     */
    public void stopped (CrawlEvent event){
        if (concat != null) {
            try {
                concat.close ();
                concat = null;
                if (useBrowser)
                    showit ();
            } catch (IOException e) {
                System.err.println (e); // FIX: use GUI when available
            }
        }
    }

    /**
     * Notify that the crawler's state was cleared.
     */
    public void cleared (CrawlEvent event){
        try {
            if (concat != null) {
                concat.close ();
                concat = null;
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

    /**
     * Notify that the crawler timed out.
     */
    public void timedOut (CrawlEvent event){
        try {
            if (concat != null) {
                concat.close ();
                concat = null;
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

    /**
     * Notify that the crawler is paused.
     */
    public void paused (CrawlEvent event){
        try {
            if (concat != null) {
                concat.rewrite ();
                if (useBrowser)
                    showit ();
            }
        } catch (IOException e) {
            System.err.println (e); // FIX: use GUI when available
        }
    }

}

