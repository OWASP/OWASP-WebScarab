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
import websphinx.*;
import websphinx.util.Constrain;

public class LinkPredicateEditor extends Panel { // FIX: consider implementing java.beans.PropertyEditor
    
    LinkFeatureChoice choice;

    /**
     * Make a LinkPredicateEditor.
     */
    public LinkPredicateEditor () {
        setLayout (new GridBagLayout ());
        choice = new LinkFeatureChoice ();
        Constrain.add (this, choice, Constrain.labelLike (0, 0));
        Constrain.add (this, choice.getArgs(), Constrain.areaLike (0, 1));
        setLinkPredicate (null);
    }

    public void setLinkPredicate (LinkPredicate pred) {
        choice.setLinkPredicate (pred);
    }

    public LinkPredicate getLinkPredicate () {
        return choice.getLinkPredicate ();
    }

}

class LinkFeatureChoice extends FeatureChoice {
    LinkFeatureArgs args = new LinkFeatureArgs ();

    final static String NULL_FEATURE = "all links";
    final static String URL_FEATURE = "URL";
    final static String HTML_FEATURE = "HTML tag";
    final static String TEXT_FEATURE = "anchor text";
    final static String LABEL_FEATURE = "labels";
    final static String SCRIPT_FEATURE = "script";

    public LinkFeatureChoice () {
        addItem (NULL_FEATURE);
        addItem (LABEL_FEATURE);
        addItem (URL_FEATURE);
        addItem (TEXT_FEATURE);
        addItem (HTML_FEATURE);            
        addItem (SCRIPT_FEATURE);
    }
    
    public Panel getArgs () {
        return args;
    }
    
    public void setLinkPredicate (LinkPredicate pred) {
        LinkPredicate neg = null;
        if (pred instanceof DualPredicate) {
            neg = (LinkPredicate)((DualPredicate)pred).getNegativePredicate ();
            pred = (LinkPredicate)((DualPredicate)pred).getPositivePredicate ();
        }

        if (pred == null) {
            select (NULL_FEATURE);
        }
        else if (pred instanceof URLPredicate) {
            URLPredicate urlpred = (URLPredicate)pred;
            URLPredicate urlneg = (URLPredicate)neg;
            select (URL_FEATURE);
            args.setURLPattern (urlpred.getPattern ().toString());
            args.setURLNegPattern (urlneg != null 
                                   ? urlneg.getPattern ().toString ()
                                   : "");
        }
        else if (pred instanceof ContentPredicate) {
            ContentPredicate contpred = (ContentPredicate)pred;
            ContentPredicate contneg = (ContentPredicate)neg;
            if (contpred.getOverHTML()) {
                select (HTML_FEATURE);
                args.setHTMLPattern (contpred.getPattern ().toString());
                args.setHTMLNegPattern (contneg != null 
                                        ? contneg.getPattern ().toString ()
                                        : "");
            }
            else {
                select (TEXT_FEATURE);
                args.setTextPattern (contpred.getPattern ().toString());
                args.setTextNegPattern (contneg != null 
                                        ? contneg.getPattern ().toString ()
                                        : "");
            }
        }
        else if (pred instanceof LabelPredicate) {
            LabelPredicate labelpred = (LabelPredicate)pred;
            select (LABEL_FEATURE);
            args.setOrTerms (labelpred.getOrTerms());
            args.setLabels (labelpred.getLabels());
        }
        else if (pred instanceof Script) {
            Script script = (Script)pred;
            select (SCRIPT_FEATURE);
            args.setScript (script.getScript ());
        }
        else {
            select (NULL_FEATURE);
        }
    }
    
    public LinkPredicate getLinkPredicate () {
        String feat = getSelectedItem ();
        if (feat.equals (URL_FEATURE))
            return makeSingleOrDual (new URLPredicate (new Wildcard (args.getURLPattern())),
                                     args.getURLNegPattern().length() == 0
                                     ? null
                                     : new URLPredicate (new Wildcard (args.getURLNegPattern())));
        else if (feat.equals (HTML_FEATURE))
            return makeSingleOrDual (new ContentPredicate (new TagExp (args.getHTMLPattern()), true),
                                     args.getHTMLNegPattern().length() == 0
                                     ? null
                                     : new ContentPredicate (new TagExp (args.getHTMLNegPattern()), true));
        else if (feat.equals (TEXT_FEATURE))
            return makeSingleOrDual (new ContentPredicate (new RegExp (args.getTextPattern()), false),
                                     args.getTextNegPattern().length() == 0
                                     ? null
                                     : new ContentPredicate (new RegExp (args.getTextNegPattern()), false));
        else if (feat.equals (LABEL_FEATURE))
            return new LabelPredicate (args.getLabels(), args.getOrTerms());
        else if (feat.equals (SCRIPT_FEATURE))
            return new Script (args.getScript (), true);
        else
            return null;
    }

    private static LinkPredicate makeSingleOrDual (LinkPredicate positive,
                                                   LinkPredicate negative) {
        return negative == null
            ? positive
            : new DualPredicate (positive, negative);
    }    
}

class LinkFeatureArgs extends Panel {

    final static String ANY_TERMS = "any";
    final static String ALL_TERMS = "all";

    TextField urlPattern;
    TextField urlNegPattern;
    TextField textPattern;
    TextField textNegPattern;
    TextField htmlPattern;
    TextField htmlNegPattern;
    TextField labels;
    Choice orTerms;
    TextArea script;
            
    public LinkFeatureArgs () {
        Panel panel;
        
        setLayout (new CardLayout ());
        
        add (LinkFeatureChoice.NULL_FEATURE, panel = new Panel ());
        
        add (LinkFeatureChoice.URL_FEATURE, panel = Constrain.makeConstrainedPanel (1, 4));
        Constrain.add (panel, new Label (" matches the wildcard expression "), Constrain.labelLike (0, 0));
        Constrain.add (panel, urlPattern = new TextField (), Constrain.fieldLike (0, 1));
        Constrain.add (panel, new Label (" but not the expression "), Constrain.labelLike (0, 2));
        Constrain.add (panel, urlNegPattern = new TextField (), Constrain.fieldLike (0, 3));

        add (LinkFeatureChoice.HTML_FEATURE, panel = Constrain.makeConstrainedPanel (1, 4));
        Constrain.add (panel, new Label (" matches the HTML tag expression "), Constrain.labelLike (0, 0));
        Constrain.add (panel, htmlPattern = new TextField (), Constrain.fieldLike (0, 1));
        Constrain.add (panel, new Label (" but not the expression "), Constrain.labelLike (0, 2));
        Constrain.add (panel, htmlNegPattern = new TextField (), Constrain.fieldLike (0, 3));

        add (LinkFeatureChoice.TEXT_FEATURE, panel = Constrain.makeConstrainedPanel (1, 4));
        Constrain.add (panel, new Label (" matches the regular expression "), Constrain.labelLike (0, 0));
        Constrain.add (panel, textPattern = new TextField (), Constrain.fieldLike (0, 1));
        Constrain.add (panel, new Label (" but not the expression "), Constrain.labelLike (0, 2));
        Constrain.add (panel, textNegPattern = new TextField (), Constrain.fieldLike (0, 3));

        add (LinkFeatureChoice.LABEL_FEATURE, panel = Constrain.makeConstrainedPanel (3, 2));
        Constrain.add (panel, new Label (" include "), Constrain.labelLike (0, 0));
        Constrain.add (panel, orTerms = new Choice (), Constrain.labelLike (1, 0));
        orTerms.addItem (ANY_TERMS);
        orTerms.addItem (ALL_TERMS);
        orTerms.select (ANY_TERMS);
        Constrain.add (panel, new Label (" of the labels "), Constrain.labelLike (2, 0));
        Constrain.add (panel, labels = new TextField (), Constrain.fieldLike (0, 1, 3));

        ScriptInterpreter interp = Context.getScriptInterpreter ();
        if (interp != null) {
            add (LinkFeatureChoice.SCRIPT_FEATURE, 
                 panel = Constrain.makeConstrainedPanel (1, 2));
            Constrain.add (panel, new Label (interp.getLanguage() + " Function (crawler, link)"), 
                           Constrain.labelLike (0, 0));
            Constrain.add (panel, script = new TextArea ("return true;\n"),
                           Constrain.areaLike (0, 1));
        }
        else {
            add (LinkFeatureChoice.SCRIPT_FEATURE, 
                 panel = Constrain.makeConstrainedPanel (1, 1));
            Constrain.add (panel, new Label ("No scripting language is available."),
                           Constrain.labelLike (0, 0));
        }
    }
    
    public void setURLPattern (String pattern) {
        urlPattern.setText (pattern);
    }

    public String getURLPattern () {
        return urlPattern.getText ();
    }

    public void setURLNegPattern (String pattern) {
        urlNegPattern.setText (pattern);
    }

    public String getURLNegPattern () {
        return urlNegPattern.getText ();
    }

    public void setTextPattern (String pattern) {
        textPattern.setText (pattern);
    }

    public String getTextPattern () {
        return textPattern.getText ();
    }

    public void setTextNegPattern (String pattern) {
        textNegPattern.setText (pattern);
    }

    public String getTextNegPattern () {
        return textNegPattern.getText ();
    }

    public void setHTMLPattern (String pattern) {
        htmlPattern.setText (pattern);
    }

    public String getHTMLPattern () {
        return htmlPattern.getText ();
    }

    public void setHTMLNegPattern (String pattern) {
        htmlNegPattern.setText (pattern);
    }

    public String getHTMLNegPattern () {
        return htmlNegPattern.getText ();
    }

    public void setLabels (String pattern) {
        labels.setText (pattern);
    }

    public String getLabels () {
        return labels.getText ();
    }
    
    public void setOrTerms (boolean orTerms) {
        this.orTerms.select (orTerms ? ANY_TERMS : ALL_TERMS);
    }
    
    public boolean getOrTerms () {
        return orTerms.getSelectedItem ().equals (ANY_TERMS);
    }

    public void setScript (String script) {
        this.script.setText (script);
    }

    public String getScript () {
        return script != null ? script.getText () : null;
    }
    
}        
