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

import java.awt.*;
abstract class FeatureChoice extends Choice
{

    public FeatureChoice () {
    }        

    public abstract Panel getArgs ();

    public synchronized void select (int pos) {
        super.select (pos);
        flipArgs ();
    }

    public synchronized void select (String item) {
        super.select (item);
        flipArgs ();
    }

    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT && event.target == this) {
            flipArgs ();
            return true;
        }
        else
            return super.handleEvent (event);
    }

    void flipArgs () {
        Panel args = getArgs();
        CardLayout layout = (CardLayout)(args.getLayout ());
        layout.show (args, getSelectedItem());
    }

}
