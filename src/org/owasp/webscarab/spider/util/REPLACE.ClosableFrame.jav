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
package org.owasp.webscarab.spider.util;
import java.awt.*;
public class ClosableFrame extends Frame 
{
    boolean hideWhenClosed = false;
    
    public ClosableFrame () {
        super ();
    }

    public ClosableFrame (String title) {
        super (title);
    }

    public ClosableFrame (boolean hideWhenClosed) {
        this();
        this.hideWhenClosed = hideWhenClosed;
    }

    public ClosableFrame (String title, boolean hideWhenClosed) {
        this (title);
        this.hideWhenClosed = hideWhenClosed;
    }        
    
    public void close () {
        if (hideWhenClosed)
            hide ();
        else            
            dispose ();
    }

    public boolean handleEvent (Event event) {
        if (event.id == Event.WINDOW_DESTROY)
            close ();
        else
            return super.handleEvent (event);
        return true;
    }
}
