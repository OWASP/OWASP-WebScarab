/*
 * Framework.java
 *
 * Created on June 16, 2004, 8:57 AM
 */

package org.owasp.webscarab.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.jar.Attributes.Name;
import java.util.logging.Logger;

import org.owasp.webscarab.httpclient.HTTPClientFactory;
import org.owasp.webscarab.model.Preferences;
import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.StoreException;

/**
 * creates a class that contains and controls the plugins.
 * @author knoppix
 */
public class Framework {
    
    private List _plugins = new ArrayList();
    
    private SiteModel _model = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private String _version;
    
    private FrameworkUI _ui = null;
    
    /**
     * Creates a new instance of Framework
     */
    public Framework() {
        extractVersionFromManifest();
        configureHTTPClient();
    }
    
    /**
     * links the framework to its GUI
     * @param ui a class implementing the necessary interface methods
     */    
    public void setUI(FrameworkUI ui) {
        _ui = ui;
    }
    
    /**
     * instructs the framework to use the provided model. The framework notifies all
     * plugins that the model has changed.
     * @param model the new SiteModel
     */    
    public void setSession(SiteModel model, String storeType, Object connection) throws StoreException {
        if (_model != null) {
            try {
                saveSessionData();
            } catch (StoreException se) {
                _logger.severe("Exception saving previous store: " + se);
            }
        }
        _model = model;
        if (_ui != null) _ui.setModel(model);
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (!plugin.isRunning()) {
                plugin.setSession(model, storeType, connection);
            } else {
                _logger.warning(plugin.getPluginName() + " is running while we are setting the model");
            }
        }
        startPlugins();
    }
    
    /**
     * provided to allow the UI to access the model at instantiation time. There is probably a better way of doing this.
     * @return the SiteModel currently loaded into the Framework
     */    
    public SiteModel getModel() {
        return _model;
    }
    
    private void extractVersionFromManifest() {
        String myClass = "/" + getClass().getName().replaceAll("\\.", "/") + ".class";
        try { 
            URL url = getClass().getResource(myClass);
            if(url.getProtocol().equals("jar")) {
                // _logger.info("URL is " + url);
                String path = url.toString();
                path = path.substring(0, path.lastIndexOf("!")+1) + "/META-INF/MANIFEST.MF";
                // _logger.info("Path is " + path);
                url = new URL(path);
                InputStream is = url.openStream();
                // _logger.info("IS is " + is);
                if (is != null) {
                    Manifest manifest = new Manifest(is);
                    Attributes common = manifest.getAttributes("common");
                    if (common != null) {
                        _version = common.getValue(Name.IMPLEMENTATION_VERSION);
                    } else {
                        _logger.severe("No common section in manifest");
                    }
                } else {
                    _logger.warning("Could not read the manifest in the JAR");
                }
            } else {
                // _logger.info("WebScarab is not packaged in a JAR");
            }
        } catch (MalformedURLException mue) {
            _logger.warning("Error creating Manifest URL: " + mue);
        } catch (IOException ioe) {
            _logger.warning("Error reading the manifest: " + ioe);
        }
        if (_version == null) _version = "unknown (local build?)";
    }
    
    /**
     * adds a new plugin into the framework
     * @param plugin the plugin to add
     */    
    public void addPlugin(Plugin plugin) {
        _plugins.add(plugin);
    }
    
    /**
     * starts all the plugins in the framework
     */    
    public void startPlugins() {
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (!plugin.isRunning()) {
                Thread t = new Thread(plugin, plugin.getPluginName());
                t.setDaemon(true);
                t.start();
            } else {
                _logger.warning(plugin.getPluginName() + " was already running");
            }
        }
    }
    
    public boolean isBusy() {
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isBusy()) return true;
        }
        return false;
    }
    
    public boolean isRunning() {
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isRunning()) return true;
        }
        return false;
    }
    
    public String[] getStatus() {
        List status = new ArrayList();
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            status.add(plugin.getPluginName() + " : " + plugin.getStatus());
        }
        return (String[]) status.toArray(new String[0]);
    }
    
    /**
     * stops all the plugins in the framework
     */    
    public boolean stopPlugins() {
        if (isBusy()) return false;
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            if (plugin.isRunning()) {
                // _logger.info("Stopping " + plugin.getPluginName());
                plugin.stop();
                // _logger.info("Done");
            } else {
                _logger.warning(plugin.getPluginName() + " was not running");
            }
        }
        return true;
    }
    
    /**
     * called to instruct the various plugins to save their current state to the store.
     * @throws StoreException if there is any problem saving the session data
     */
    public void saveSessionData() throws StoreException {
        if (!isRunning()) throw new StoreException("Framework is not active!");
        if (!stopPlugins()) {
            throw new StoreException("Unable to stop plugins");
        }
        
        StoreException storeException = null;
        _logger.info("Flushing model");
        _model.flush();
        _logger.info("Done");
        Iterator it = _plugins.iterator();
        while (it.hasNext()) {
            Plugin plugin = (Plugin) it.next();
            try {
                _logger.info("Flushing " + plugin.getPluginName());
                plugin.flush();
                _logger.info("Done");
            } catch (StoreException se) {
                if (storeException == null) storeException = se;
                _logger.severe("Error saving data for " + plugin.getPluginName() + ": " + se);
            }
        }
        
        if (storeException != null) throw storeException;
    }
    
    /**
     * instructs all plugins to stop, calls flush() on the model, and each of the plugins,
     * saves the properties in the user directory, and calls System.exit(0);
     * @throws StoreException if any are thrown while flushing the model or plugins
     */    
    public void exit() throws StoreException {
        if (_model != null) saveSessionData();
        try {
            Preferences.savePreferences();
        } catch (IOException ioe) {
            _logger.severe("Could not save preferences: " + ioe);
        }
        System.exit(0);
    }
    
    /**
     * returns the build version of WebScarab. This is extracted from the webscarab.jar
     * Manifest, if webscarab is running from a jar.
     * @return the version string
     */    
    public String getVersion() {
        return _version;
    }
    
    private void configureHTTPClient() {
        HTTPClientFactory factory = HTTPClientFactory.getInstance();
        String prop = null;
        String value;
        int colon;
        try {
        	// FIXME for some reason, we get "" instead of null for value,
        	// and do not use our default value???
            prop = "WebScarab.httpProxy";
            value = Preferences.getPreference(prop);
            if (value == null || value.equals("")) value = ":3128";
            colon = value.indexOf(":");
            factory.setHttpProxy(value.substring(0,colon), Integer.parseInt(value.substring(colon+1).trim()));
            
            prop = "WebScarab.httpsProxy";
            value = Preferences.getPreference(prop);
            if (value == null || value.equals("")) value = ":3128";
            colon = value.indexOf(":");
            factory.setHttpsProxy(value.substring(0,colon), Integer.parseInt(value.substring(colon+1).trim()));
            
            prop = "WebScarab.noProxy";
            value = Preferences.getPreference(prop, "");
            if (value == null) value = "";
            factory.setNoProxy(value.split(" *, *"));
            
            prop = "WebScarab.clientCertificateFile";
            String file = Preferences.getPreference(prop, "");
            prop = "WebScarab.keystorePassword";
            String keystorePass = Preferences.getPreference(prop, "");
            prop = "WebScarab.keyPassword";
            String keyPass = Preferences.getPreference(prop, "");
            
            factory.setClientCertificateFile(file, keystorePass, keyPass);
            
        } catch (NumberFormatException nfe) {
            _logger.warning("Error parsing property " + prop + ": " + nfe);
        } catch (Exception e) {
            _logger.warning("Error configuring the HTTPClient property " + prop + ": " + e);
        }
    }

}
