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
import java.io.*;
import java.net.URL;
import websphinx.*;
import websphinx.util.Constrain;
import websphinx.util.PopupDialog;
import websphinx.util.TabPanel;
import websphinx.util.BorderPanel;
import websphinx.util.ClosableFrame;

public class WorkbenchControlPanel extends PopupDialog {
    WebGraph g;
    WebOutline o;

    Choice nodeChoice;
    Choice pageChoice;
    Choice linkChoice;
    Checkbox automatic;

    Button applyButton;
    Button okButton;
    Button cancelButton;

    public WorkbenchControlPanel (WebGraph g, WebOutline o) {
        super (getFrame (g != null ? (Component)g : (Component)o), "Workbench Control Panel", true);

        this.g = g;
        this.o = o;

        setLayout (new GridBagLayout ());

        Constrain.add (this, new Label ("Display:"),
                       Constrain.labelLike (0, 0));
        Constrain.add (this, nodeChoice = new Choice (),
                       Constrain.fieldLike (1, 0));
        nodeChoice.addItem ("icons");
        nodeChoice.addItem ("titles");
        nodeChoice.addItem ("absolute URLs");
        nodeChoice.addItem ("relative URLs");
        nodeChoice.select (g != null ? g.defaultRendering : o.defaultRendering+1);

        Constrain.add (this, new Label ("Pages:"),
                       Constrain.labelLike (0, 1));
        Constrain.add (this, pageChoice = new Choice (),
                       Constrain.fieldLike (1, 1));
        pageChoice.addItem ("visited pages");
        pageChoice.addItem ("all pages");

        Constrain.add (this, new Label ("Links:"),
                       Constrain.labelLike (0, 2));
        Constrain.add (this, linkChoice = new Choice (),
                       Constrain.fieldLike (1, 2));
        linkChoice.addItem ("tree links");
        linkChoice.addItem ("all links");

        if (g != null)
            switch (g.defaultFilter) {
                case WebGraph.NO_LINKS:
                case WebGraph.RETRIEVED_LINKS:
                    pageChoice.select (0);
                    linkChoice.select (0);
                    break;
                case WebGraph.WALKED_LINKS:
                case WebGraph.TREE_LINKS:
                    pageChoice.select (1);
                    linkChoice.select (0);
                    break;
                case WebGraph.ALL_LINKS:
                    pageChoice.select (1);
                    linkChoice.select (1);
                    break;
            }
        else {
            pageChoice.select (o.defaultFilter == WebOutline.ALL_LINKS ? 1 : 0);
            linkChoice.disable ();
        }


        Constrain.add (this, automatic = new Checkbox ("Automatic layout"),
                       Constrain.labelLike (1, 3));
        if (g != null)
            automatic.setState (g.getAutomaticLayout ());
        else
            g.disable ();

        Panel panel;
        Constrain.add (this, panel = new Panel(),
                       Constrain.centered (Constrain.labelLike (0, 4, 2)));
        panel.add (applyButton = new Button ("Apply"));
        panel.add (okButton = new Button ("OK"));
        panel.add (cancelButton = new Button ("Cancel"));

        pack ();
    }

    void writeBack () {
        if (g != null) g.setAutomaticLayout (automatic.getState ());

        switch (nodeChoice.getSelectedIndex ()) {
        case 0:
            if (g != null) g.setNodeRendering (WebGraph.ICON);
            if (o != null) o.setNodeRendering (WebOutline.TITLE);
            break;
        case 1:
            if (g != null) g.setNodeRendering (WebGraph.TITLE);
            if (o != null) o.setNodeRendering (WebOutline.TITLE);
            break;
        case 2:
            if (g != null) g.setNodeRendering (WebGraph.ABSOLUTE_URL);
            if (o != null) o.setNodeRendering (WebOutline.ABSOLUTE_URL);
            break;
        case 3:
            if (g != null) g.setNodeRendering (WebGraph.RELATIVE_URL);
            if (o != null) o.setNodeRendering (WebOutline.RELATIVE_URL);
            break;
        }

        switch (pageChoice.getSelectedIndex ()) {
        case 0:
            if (g != null) g.setLinkFilter (WebGraph.RETRIEVED_LINKS);
            if (o != null) o.setLinkFilter (WebOutline.RETRIEVED_LINKS);
            break;
        case 1:
            if (o != null) o.setLinkFilter (WebOutline.WALKED_LINKS);
            switch (linkChoice.getSelectedIndex ()) {
            case 0:
                if (g != null) g.setLinkFilter (WebGraph.WALKED_LINKS);
                break;
            case 1:
                if (g != null) g.setLinkFilter (WebGraph.ALL_LINKS);
                break;
            }
            break;
        }
    }

    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target == applyButton)
                writeBack ();
            else if (event.target == okButton) {
                writeBack ();
                close ();
            }
            else if (event.target == cancelButton)
                close ();
            else
                return super.handleEvent (event);
        }
        else if (event.id == Event.WINDOW_DESTROY)
            dispose ();
        else
            return super.handleEvent (event);

        return true;
    }
}
