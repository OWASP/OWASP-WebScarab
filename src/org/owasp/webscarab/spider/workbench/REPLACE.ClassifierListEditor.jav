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

public class ClassifierListEditor extends Panel {

    List classifierList;
    Button newClassifierButton;
    Button loadClassifierButton;
    Button removeClassifierButton;

    Crawler crawler;
    Classifier[] classifiers;

    public ClassifierListEditor () {
        setLayout (new GridBagLayout ());

        Constrain.add (this, new Label ("Classifiers:"), Constrain.labelLike (0, 0));
        Constrain.add (this, classifierList = new List (5, false), Constrain.areaLike (0, 1));

        Panel panel = new Panel ();
        Constrain.add (this, panel, Constrain.fieldLike (0, 2));

        panel.add (newClassifierButton = new Button ("New..."));
        panel.add (loadClassifierButton = new Button ("Load..."));
        loadClassifierButton.disable ();
        panel.add (removeClassifierButton = new Button ("Remove"));
        removeClassifierButton.disable ();
    }

    public boolean handleEvent (Event event) {
        if (event.target == classifierList) {
            if (classifierList.getSelectedIndex () != -1)
                removeClassifierButton.enable ();
            else
                removeClassifierButton.disable ();
        }
        else if (event.id == Event.ACTION_EVENT) {
            if (event.target == newClassifierButton)
                newClassifier (null);
            else if (event.target == loadClassifierButton)
                    ; // NIY
            else if (event.target == removeClassifierButton)
                removeSelectedClassifier ();
            else
                return super.handleEvent (event);
        }
        else
            return super.handleEvent (event);

        return true;
    }

    public void setCrawler (Crawler crawler) {
        this.crawler = crawler;
        scan ();
    }

    public Crawler getCrawler () {
        return crawler;
    }

    private void newClassifier (String className) {
        if (className == null || className.length() == 0) {
            className = PopupDialog.ask (this,
                                         "New Classifier",
                                         "Create an instance of class:");
            if (className == null)
                return;
        }
        
        try {
            Class classifierClass = (Class)Class.forName (className);
            Classifier cl = (Classifier)classifierClass.newInstance ();
            crawler.addClassifier (cl);
        } catch (Exception e) {
            PopupDialog.warn (this, 
                              "Error", 
                              e.toString());
        }
        
        scan ();
    }

    private void removeSelectedClassifier () {
        int i = classifierList.getSelectedIndex ();
        if (i < 0 || i >= classifiers.length) {
            removeClassifierButton.disable ();
            return;
        }

        crawler.removeClassifier (classifiers[i]);
        scan ();        
    }

    private void scan () {
        classifiers = crawler.getClassifiers ();
        classifierList.clear ();
        for (int i=0; i<classifiers.length; ++i)
            classifierList.addItem (classifiers[i].getClass().getName());
    }
}
