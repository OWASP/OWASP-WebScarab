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
import websphinx.util.PopupDialog;

public class CrawlerEditor extends Panel {

    Crawler crawler;

    Label domainLabel;
    Choice domainChoice;

    Label typeLabel;
    Choice typeChoice;

    Label urlLabel;
    TextComponent urlField;

    Label depthLabel;
    Label depthLabel2;
    TextComponent depthField;

    Choice searchOrderChoice;

    public CrawlerEditor () {
        setLayout (new GridBagLayout ());

    	Constrain.add (this, domainLabel = new Label("Crawl:"), Constrain.labelLike (0, 0));
        Constrain.add (this, domainChoice = new Choice (), Constrain.labelLike (1, 0, 2));
        domainChoice.addItem ("the subtree");
        domainChoice.addItem ("the server");
        domainChoice.addItem ("the Web");

    	Constrain.add (this, typeLabel = new Label("Using:"), Constrain.labelLike (3, 0));
        Constrain.add (this, typeChoice = new Choice (), Constrain.fieldLike (4, 0));
        typeChoice.addItem ("hyperlinks");
        typeChoice.addItem ("images+hyperlinks");
        typeChoice.addItem ("all links");

        Constrain.add (this, urlLabel = new Label ("Starting URLs:"), Constrain.labelLike (0, 1));
        Constrain.add (this, urlField = new TextArea(3, 40), Constrain.areaLike (1, 1, 4));
        
        Constrain.add (this, depthLabel = new Label ("Depth:"), Constrain.labelLike (0, 2));
        Constrain.add (this, depthField = new TextField (4), Constrain.fieldLike (1, 2));
        Constrain.add (this, depthLabel2 = new Label ("  hops"), Constrain.labelLike (2, 2));
        Constrain.add (this, searchOrderChoice = new Choice (), Constrain.fieldLike (4, 2));
	    searchOrderChoice.addItem ("Depth first");
	    searchOrderChoice.addItem ("Breadth first");
    }

    public boolean handleEvent (Event event) {
        if (event.id == Event.ACTION_EVENT) {
            if (event.target == domainChoice)
                configureDomain ();
            else if (event.target == urlField)
                configureURL ();
            else if (event.target == depthField)
                configureDepth ();
            else if (event.target == searchOrderChoice)
                configureDepthFirst ();
            else
                return super.handleEvent (event);
        }
        else if (event.id == Event.LOST_FOCUS) {
            if (event.target == urlField)
                configureURL ();
            else if (event.target == depthField)
                configureDepth ();
            else
                return super.handleEvent (event);
        }
        else
            return super.handleEvent (event);

        return true;
    }

    public void setCrawler (Crawler crawler) {
        this.crawler = crawler;

        String[] domain = crawler.getDomain ();
        if (domain == Crawler.SERVER)
            domainChoice.select (1);
        else if (domain == Crawler.SUBTREE)
            domainChoice.select (0);
        else
            domainChoice.select (2);

        String[] type = crawler.getLinkType ();
        if (type == Crawler.HYPERLINKS_AND_IMAGES)
            typeChoice.select (1);
        else if (type == Crawler.ALL_LINKS)
            typeChoice.select (2);
        else
            typeChoice.select (0);

        urlField.setText (crawler.getRootHrefs ());
        depthField.setText (String.valueOf (crawler.getMaxDepth ()));
        searchOrderChoice.select (crawler.getDepthFirst () ? 0 : 1);
    }

    public Crawler getCrawler () {
        if (configureDomain ()
            && configureType ()
            && configureURL ()
            && configureDepth ()
            && configureDepthFirst ())
            return crawler;
        else
            return null;
    }

    boolean configureDomain () {
        switch (domainChoice.getSelectedIndex ()) {
            case 2: // the Web
                crawler.setDomain (Crawler.WEB);
                break;
            case 1: // a server
                crawler.setDomain (Crawler.SERVER);
                break;
            case 0: // a subtree
                crawler.setDomain (Crawler.SUBTREE);
                break;
	        default:
	            throw new RuntimeException ("unknown state " + domainChoice.getSelectedIndex ());
        }
        return true;
    }

    boolean configureType () {
        switch (typeChoice.getSelectedIndex ()) {
            case 0:
                crawler.setLinkType (Crawler.HYPERLINKS);
                break;
            case 1:
                crawler.setLinkType (Crawler.HYPERLINKS_AND_IMAGES);
                break;
            case 2:
                crawler.setLinkType (Crawler.ALL_LINKS);
                break;
	        default:
	            throw new RuntimeException ("unknown state " + typeChoice.getSelectedIndex ());
        }
        return true;
    }

    String lastURL = null;

    boolean configureURL () {
        String hrefs = urlField.getText();
	    try {
		    crawler.setRootHrefs (hrefs);
		    lastURL = hrefs;
		    return true;
		} catch (java.net.MalformedURLException ex) {
		    if (lastURL == null || !lastURL.equals (hrefs)) {
                PopupDialog.warn (this, "Error", "Improperly formed URL:\n" + hrefs);
                urlField.selectAll ();
                urlField.requestFocus ();
            }
            lastURL = hrefs;
            return false;
		}
	}

	String lastDepth = null;

	boolean configureDepth () {
	    String depth = depthField.getText ();
	    try {
		    crawler.setMaxDepth (Integer.parseInt (depth));
		    lastDepth = depth;
		    return true;
		} catch (NumberFormatException ex) {
		    if (lastDepth == null || !lastDepth.equals (depth)) {
                PopupDialog.warn (this, "Error", "Depth must be an integer");
                depthField.selectAll ();
                depthField.requestFocus ();
            }
            lastDepth = depth;
            return false;
		}
	}

    boolean configureDepthFirst () {
        crawler.setDepthFirst (searchOrderChoice.getSelectedIndex () == 0);
        return true;
    }
}
