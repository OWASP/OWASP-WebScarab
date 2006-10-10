/*
 * WebScarab.java
 *
 * Created on 06 February 2006, 04:59
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab;

import java.io.IOException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingUtilities;
import no.geosoft.cc.ui.SplashScreen;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.compare.Compare;
import org.owasp.webscarab.plugin.compare.swing.ComparePanel;
import org.owasp.webscarab.plugin.extensions.Extensions;
import org.owasp.webscarab.plugin.extensions.swing.ExtensionsPanel;
import org.owasp.webscarab.plugin.fragments.Fragments;
import org.owasp.webscarab.plugin.fragments.swing.FragmentsPanel;
import org.owasp.webscarab.plugin.fuzz.Fuzzer;
import org.owasp.webscarab.plugin.fuzz.swing.FuzzerPanel;
import org.owasp.webscarab.plugin.manualrequest.ManualRequest;
import org.owasp.webscarab.plugin.manualrequest.swing.ManualRequestPanel;
import org.owasp.webscarab.plugin.proxy.BeanShell;
import org.owasp.webscarab.plugin.proxy.BrowserCache;
import org.owasp.webscarab.plugin.proxy.CookieTracker;
import org.owasp.webscarab.plugin.proxy.ManualEdit;
import org.owasp.webscarab.plugin.proxy.Proxy;
import org.owasp.webscarab.plugin.proxy.RevealHidden;
import org.owasp.webscarab.plugin.proxy.swing.BeanShellPanel;
import org.owasp.webscarab.plugin.proxy.swing.ManualEditPanel;
import org.owasp.webscarab.plugin.proxy.swing.MiscPanel;
import org.owasp.webscarab.plugin.proxy.swing.ProxyPanel;
import org.owasp.webscarab.plugin.scripted.Scripted;
import org.owasp.webscarab.plugin.scripted.swing.ScriptedPanel;
import org.owasp.webscarab.plugin.search.Search;
import org.owasp.webscarab.plugin.search.swing.SearchPanel;
import org.owasp.webscarab.plugin.sessionid.SessionIDAnalysis;
import org.owasp.webscarab.plugin.sessionid.swing.SessionIDPanel;
import org.owasp.webscarab.plugin.spider.Spider;
import org.owasp.webscarab.plugin.spider.swing.SpiderPanel;
import org.owasp.webscarab.plugin.webservice.WebService;
import org.owasp.webscarab.plugin.webservice.swing.WebServicePanel;
import org.owasp.webscarab.plugin.xsscrlf.XSSCRLF;
import org.owasp.webscarab.plugin.xsscrlf.swing.XSSCRLFPanel;
import org.owasp.webscarab.ui.swing.Lite;
import org.owasp.webscarab.ui.swing.UIFramework;
import org.owasp.webscarab.util.TextFormatter;
import org.owasp.webscarab.util.swing.ExceptionHandler;

/**
 *
 * @author rdawes
 */
public class WebScarab {
    
    /** Creates a new instance of WebScarab */
    private WebScarab() {
    }
    
    /* This class exists purely to ensure that the
     * program version information is properly loaded at run-time
     *
     * It may eventually become a dispatcher for different versions
     * of user interfaces
     */
    public static void main(String[] args) {
        
        System.setProperty("sun.awt.exception.handler", ExceptionHandler.class.getName());
        
        final SplashScreen splash = new SplashScreen("/org/owasp/webscarab/webscarab_logo.gif");
        splash.open(10000);
        initLogging();
        
        try {
            Preferences.loadPreferences(null);
        } catch (IOException ioe) {
            System.err.println("Error loading preferences: " + ioe);
            System.exit(1);
        }
        
        Framework framework = new Framework();
        
        boolean lite = Boolean.valueOf(Preferences.getPreference("WebScarab.lite", "true")).booleanValue();
        
        if (args != null && args.length > 0) {
            if (args[0].equalsIgnoreCase("lite")) {
                lite = true;
                if (args.length>1) {
                    String[] trim = new String[args.length-1];
                    System.arraycopy(args, 1, trim, 0, args.length-1);
                    args = trim;
                } else {
                    args = new String[0];
                }
            }
        }
        
        if (! lite) {
            final UIFramework uif = new UIFramework(framework);
            ExceptionHandler.setParentComponent(uif);
            loadAllPlugins(framework, uif);
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        uif.setVisible(true);
                        uif.toFront();
                        uif.requestFocus();
                        splash.close();
                    }
                });
            } catch (Exception e) {
                System.err.println("Error loading GUI: " + e.getMessage());
                System.exit(1);
            }
            uif.run();
        } else {
            final Lite uif = new Lite(framework);
            ExceptionHandler.setParentComponent(uif);
            loadLitePlugins(framework, uif);
            try {
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                        uif.setVisible(true);
                        uif.toFront();
                        uif.requestFocus();
                        splash.close();
                    }
                });
            } catch (Exception e) {
                System.err.println("Error loading GUI: " + e.getMessage());
                System.exit(1);
            }
            uif.run();
        }
        
        try {
            Preferences.savePreferences();
        } catch (IOException ioe) {
            System.err.println("Could not save preferences: " + ioe);
        }
        System.exit(0);
    }
    
    private static void initLogging() {
        Logger logger = Logger.getLogger("org.owasp.webscarab");
        logger.setUseParentHandlers(false);
        Handler ch = new ConsoleHandler();
        ch.setFormatter(new TextFormatter());
        logger.addHandler(ch);
        ch.setLevel(Level.FINE);
    }
    
    public static void loadAllPlugins(Framework framework, UIFramework uif) {
        Proxy proxy = new Proxy(framework);
        framework.addPlugin(proxy);
        ProxyPanel proxyPanel = new ProxyPanel(proxy);
        uif.addPlugin(proxyPanel);
        
        ManualEdit me = new ManualEdit();
        proxy.addPlugin(me);
        proxyPanel.addPlugin(new ManualEditPanel(me));
        BeanShell bs = new BeanShell(framework);
        proxy.addPlugin(bs);
        proxyPanel.addPlugin(new BeanShellPanel(bs));
        RevealHidden rh = new RevealHidden();
        proxy.addPlugin(rh);
        BrowserCache bc = new BrowserCache();
        proxy.addPlugin(bc);
        CookieTracker ct = new CookieTracker(framework);
        proxy.addPlugin(ct);
        proxyPanel.addPlugin(new MiscPanel(rh, bc, ct));
        
        ManualRequest manualRequest = new ManualRequest(framework);
        framework.addPlugin(manualRequest);
        uif.addPlugin(new ManualRequestPanel(manualRequest));
        
        WebService webservice = new WebService(framework);
        framework.addPlugin(webservice);
        uif.addPlugin(new WebServicePanel(webservice));
        
        Spider spider = new Spider(framework);
        framework.addPlugin(spider);
        uif.addPlugin(new SpiderPanel(spider));
        
        Extensions extensions = new Extensions(framework);
        framework.addPlugin(extensions);
        uif.addPlugin(new ExtensionsPanel(extensions));
        
        XSSCRLF xsscrlf = new XSSCRLF(framework);
        framework.addPlugin(xsscrlf);
        uif.addPlugin(new XSSCRLFPanel(xsscrlf));
        
        SessionIDAnalysis sessionIDAnalysis = new SessionIDAnalysis(framework);
        framework.addPlugin(sessionIDAnalysis);
        uif.addPlugin(new SessionIDPanel(sessionIDAnalysis));
        
        Scripted scripted = new Scripted(framework);
        framework.addPlugin(scripted);
        uif.addPlugin(new ScriptedPanel(scripted));
        
        Fragments fragments = new Fragments(framework);
        framework.addPlugin(fragments);
        uif.addPlugin(new FragmentsPanel(fragments));
        
        Fuzzer fuzzer = new Fuzzer(framework);
        framework.addPlugin(fuzzer);
        FuzzerPanel fuzzerPanel = new FuzzerPanel(fuzzer);
        uif.addPlugin(fuzzerPanel);
        
        Compare compare = new Compare(framework);
        framework.addPlugin(compare);
        ComparePanel comparePanel = new ComparePanel(compare);
        uif.addPlugin(comparePanel);
        
        Search search = new Search(framework);
        framework.addPlugin(search);
        SearchPanel searchPanel = new SearchPanel(search);
        uif.addPlugin(searchPanel);
    }
    
    public static void loadLitePlugins(Framework framework, Lite uif) {
        Proxy proxy = new Proxy(framework);
        framework.addPlugin(proxy);
        ManualEdit me = new ManualEdit();
        proxy.addPlugin(me);
        uif.addPanel("Intercept", new ManualEditPanel(me));
        
        RevealHidden rh = new RevealHidden();
        proxy.addPlugin(rh);
        uif.setRevealHiddean(rh);
        
        SessionIDAnalysis sessionIDAnalysis = new SessionIDAnalysis(framework);
        framework.addPlugin(sessionIDAnalysis);
        uif.addPluginEnhancements(new SessionIDPanel(sessionIDAnalysis));
        
        Fragments fragments = new Fragments(framework);
        framework.addPlugin(fragments);
        uif.addPluginEnhancements(new FragmentsPanel(fragments));
    }
    
}
