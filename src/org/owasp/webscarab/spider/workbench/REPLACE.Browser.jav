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
import java.applet.AppletContext;
import java.io.File;
import java.net.URL;
import java.net.MalformedURLException;

public class Browser implements LinkViewListener {
    protected AppletContext context;
    protected String frameName;

    public Browser (AppletContext context) {
        this.context = context;
        frameName = null;
    }

    public Browser (AppletContext context, String frameName) {
        this.context = context;
        this.frameName = frameName;
    }

    public void show (Page page) {
        URL url = page.getURL ();

        if (url != null)
            show (url);
        else {
            // assume page was dynamically-generated
            // save it to a temporary file, and show that
            try {
                File f = SecurityPolicy.getPolicy().makeTemporaryFile ("sphinx", ".html");
                HTMLTransformer out = new HTMLTransformer (f.toString());
                out.writePage (page);
                out.close ();
                show (Link.FileToURL (f));
            } catch (Exception e) {
                System.err.println (e); // FIX: use GUI to report error
            }
        }
    }

    public void show (Link link) {
        show (link.getURL ());
    }

    public void show (URL url) {
        if (frameName != null)
            context.showDocument (url, frameName);
        else
            context.showDocument (url);
    }

    public void show (File file) {
      try {
        show (Link.FileToURL (file));
      } catch (MalformedURLException e) {
      }
    }

    public void viewLink (LinkViewEvent event) {
        show (event.getLink ());
    }
}
