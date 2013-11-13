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

import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import no.geosoft.cc.ui.SplashScreen;

import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
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
import org.owasp.webscarab.plugin.identity.Identity;
import org.owasp.webscarab.plugin.identity.swing.IdentityPanel;
import org.owasp.webscarab.plugin.manualrequest.ManualRequest;
import org.owasp.webscarab.plugin.manualrequest.swing.ManualRequestPanel;
import org.owasp.webscarab.plugin.openid.OpenId;
import org.owasp.webscarab.plugin.openid.OpenIdProxy;
import org.owasp.webscarab.plugin.openid.swing.OpenIdPanel;
import org.owasp.webscarab.plugin.proxy.BeanShell;
import org.owasp.webscarab.plugin.proxy.BrowserCache;
import org.owasp.webscarab.plugin.proxy.CookieTracker;
import org.owasp.webscarab.plugin.proxy.ListenerSpec;
import org.owasp.webscarab.plugin.proxy.ManualEdit;
import org.owasp.webscarab.plugin.proxy.Proxy;
import org.owasp.webscarab.plugin.proxy.ProxyUI;
import org.owasp.webscarab.plugin.proxy.RevealHidden;
import org.owasp.webscarab.plugin.proxy.swing.BeanShellPanel;
import org.owasp.webscarab.plugin.proxy.swing.ManualEditPanel;
import org.owasp.webscarab.plugin.proxy.swing.MiscPanel;
import org.owasp.webscarab.plugin.proxy.swing.ProxyPanel;
import org.owasp.webscarab.plugin.saml.Saml;
import org.owasp.webscarab.plugin.saml.SamlProxy;
import org.owasp.webscarab.plugin.saml.swing.SamlPanel;
import org.owasp.webscarab.plugin.scripted.Scripted;
import org.owasp.webscarab.plugin.scripted.swing.ScriptedPanel;
import org.owasp.webscarab.plugin.search.Search;
import org.owasp.webscarab.plugin.search.swing.SearchPanel;
import org.owasp.webscarab.plugin.sessionid.SessionIDAnalysis;
import org.owasp.webscarab.plugin.sessionid.swing.SessionIDPanel;
import org.owasp.webscarab.plugin.spider.Spider;
import org.owasp.webscarab.plugin.spider.swing.SpiderPanel;
import org.owasp.webscarab.plugin.wsfed.WSFederation;
import org.owasp.webscarab.plugin.wsfed.swing.WSFederationPanel;
import org.owasp.webscarab.plugin.xsscrlf.XSSCRLF;
import org.owasp.webscarab.plugin.xsscrlf.swing.XSSCRLFPanel;
import org.owasp.webscarab.ui.swing.Lite;
import org.owasp.webscarab.ui.swing.UIFramework;
import org.owasp.webscarab.ui.swing.WebScarabUI;
import org.owasp.webscarab.util.TextFormatter;
import org.owasp.webscarab.util.swing.ExceptionHandler;
import org.owasp.webscarab.util.swing.TextComponentContextMenu;

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
        try {
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

            // Provide default Copy/Paste/etc actions on text components
            Toolkit.getDefaultToolkit().getSystemEventQueue().push(new TextComponentContextMenu());

            Framework framework = new Framework();

            boolean lite = Boolean.valueOf(Preferences.getPreference("WebScarab.lite", "false")).booleanValue();

            File t = null;
            if (args != null && args.length == 1) {
            	t = new File(args[0]);
            }
            final File session = t;
            
            final WebScarabUI ui;
            
            if (! lite) {
            	UIFramework uif = new UIFramework(framework);
                loadAllPlugins(framework, uif);
                ui = uif;
            } else {
            	Lite uif = new Lite(framework);
                loadLitePlugins(framework, uif);
                ui = uif;
            }
            try {
            	ExceptionHandler.setParentComponent(ui.getFrame());
                SwingUtilities.invokeAndWait(new Runnable() {
                    public void run() {
                    	JFrame frame = ui.getFrame();
                        frame.setVisible(true);
                        frame.toFront();
                        frame.requestFocus();
                        splash.close();
                		if (session != null && session.isDirectory())
                			ui.loadSession(session);
                		else
                	        ui.createTemporarySession();

                	}
                });
                ui.run();
            } catch (Exception e) {
                System.err.println("Error loading GUI: " + e.getMessage());
                e.printStackTrace();
                System.exit(1);
            }
        } catch (Throwable t) {
            t.printStackTrace();
            JOptionPane.showMessageDialog(null, t, "Error!", JOptionPane.ERROR_MESSAGE);
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
        logger.setLevel(Level.ALL);
        logger.addHandler(ch);
        // Preferences are not initialized yet, therefore use system properties
        String consoleLogLevel = System.getProperty("WebScarab.ConsoleLogLevel", "FINE");
        try {
            ch.setLevel(Level.parse(consoleLogLevel));
        } catch (IllegalArgumentException ex) {
            ch.setLevel(Level.FINE);
            logger.warning("Unrecognized console log level " + consoleLogLevel);
        }
    }
    
    public static void loadAllPlugins(Framework framework, WebScarabUI uif) {
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
        SamlProxy samlProxy = new SamlProxy();
        proxy.addPlugin(samlProxy);
        OpenIdProxy openIdProxy = new OpenIdProxy();
        proxy.addPlugin(openIdProxy);
        
        ManualRequest manualRequest = new ManualRequest(framework);
        framework.addPlugin(manualRequest);
        uif.addPlugin(new ManualRequestPanel(manualRequest));
        
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
        
        Saml saml = new Saml(framework, samlProxy);
		framework.addPlugin(saml);
		SamlPanel samlPanel = new SamlPanel(saml);
		uif.addPlugin(samlPanel);
        
        OpenId openId = new OpenId(framework, openIdProxy);
        framework.addPlugin(openId);
        OpenIdPanel openIdPanel = new OpenIdPanel(openId);
        uif.addPlugin(openIdPanel);
        
        WSFederation wsFed = new WSFederation(framework);
        framework.addPlugin(wsFed);
        WSFederationPanel wsFedPanel = new WSFederationPanel(wsFed);
        uif.addPlugin(wsFedPanel);
		
		Identity identity = new Identity(framework);
		framework.addPlugin(identity);
		IdentityPanel identityPanel = new IdentityPanel(identity);
		uif.addPlugin(identityPanel);
    }
    
    public static void loadLitePlugins(Framework framework, Lite uif) {
        Proxy proxy = new Proxy(framework);
        framework.addPlugin(proxy);
        ManualEdit me = new ManualEdit();
        proxy.addPlugin(me);
        proxy.setUI(new LiteProxyUI(uif));
        uif.addPanel("Intercept", new ManualEditPanel(me));
        
        RevealHidden rh = new RevealHidden();
        proxy.addPlugin(rh);
        uif.setRevealHidden(rh);
        
        SessionIDAnalysis sessionIDAnalysis = new SessionIDAnalysis(framework);
        framework.addPlugin(sessionIDAnalysis);
        uif.addPluginEnhancements(new SessionIDPanel(sessionIDAnalysis));
        
        Fragments fragments = new Fragments(framework);
        framework.addPlugin(fragments);
        uif.addPluginEnhancements(new FragmentsPanel(fragments));
    }
    
    private static class LiteProxyUI implements ProxyUI {

        private WebScarabUI lite;
        
        public LiteProxyUI(WebScarabUI lite) {
            this.lite = lite;
        }
        public void aborted(ConversationID id, String reason) {
        }

        public void proxyAdded(ListenerSpec spec) {
        }

        public void proxyRemoved(ListenerSpec spec) {
        }

        public void proxyStarted(ListenerSpec spec) {
        }

        public void proxyStartError(final ListenerSpec spec, final IOException ioe) {
            if (SwingUtilities.isEventDispatchThread()) {
                JOptionPane.showMessageDialog(lite.getFrame(), new String[] {"Error starting proxy listener: ", spec.toString(), ioe.toString()}, "Error", JOptionPane.ERROR_MESSAGE);
            } else {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        proxyStartError(spec, ioe);
                    }
                });
            }
        }

        public void proxyStopped(ListenerSpec spec) {
        }

        public void received(ConversationID id, String status) {
        }

        public void requested(ConversationID id, String method, HttpUrl url) {
        }

        public String getPluginName() {
            return "Proxy";
        }

        public void setEnabled(boolean enabled) {
        }
        
    }
    
}
