/*
 * Fragments.java
 *
 * Created on August 25, 2004, 10:45 PM
 */

package org.owasp.webscarab.plugin.fragments;

import java.io.File;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Set;
import java.util.logging.Logger;
import java.util.Date;

import org.htmlparser.nodes.RemarkNode;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.Cookie;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.SiteModelAdapter;
import org.owasp.webscarab.parser.Parser;
import org.owasp.webscarab.plugin.Plugin;
import org.owasp.webscarab.plugin.PluginUI;

import org.owasp.webscarab.util.Encoding;

/**
 * This plugin looks for comments and scripts in the source of HTML pages.
 * @author knoppix
 */
public class Fragments extends Plugin {
    
    private Thread _runThread = null;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private boolean _stopping = false;
    private Listener _listener = null;
    
    private SiteModel _model = null;
    
    private FragmentsStore _store = null;
    
    private String _status = "Stopped";
    
    private FragmentsUI _ui = null;
    
    /**
     * Creates a new instance of Fragments
     * @param props contains the user's configuration properties
     */
    public Fragments() {
    }
    
    /**
     * Sets the model that this plugin uses
     * @param model the new SiteModel to listen to
     */    
    public void setSession(SiteModel model, String storeType, Object connection) throws StoreException {
        if (_model != null && _listener != null) _model.removeSiteModelListener(_listener);
        _model = model;
        if (storeType.equals("FileSystem") && (connection instanceof File)) {
            _store = new FileSystemStore((File) connection);
            _listener = new Listener();
            model.addSiteModelListener(_listener);
        } else {
            throw new StoreException("Store type '" + storeType + "' is not supported in " + getClass().getName());
        }
        if (_ui != null) _ui.setModel(model);
    }
    
    public void setUI(FragmentsUI ui) {
        _ui = ui;
    }
    
    public int getFragmentTypeCount() {
        return _store.getFragmentTypeCount();
    }
    
    public String getFragmentType(int index) {
        return _store.getFragmentType(index);
    }
    
    public int getFragmentCount(String type) {
        return _store.getFragmentCount(type);
    }
    
    public String getFragment(String key) {
        return _store.getFragment(key);
    }
    
    public String getFragmentKeyAt(String type, int position) {
        return _store.getFragmentKeyAt(type, position);
    }
    
    public int indexOfFragment(String type, String key) {
        return _store.indexOfFragment(type, key);
    }
    
    /**
     * used by the user interface to access any comments that have been observed in
     * HTML returned in response to queries for the specified URL
     * @param url the url in question
     * @return the text of any comments, or a zero length array if there were none
     */    
    public String[] getUrlComments(HttpUrl url) {
        String[] keys;
        if (url == null) {
            Set keySet = new HashSet();
            collectUrlProperties(null, "COMMENTS", keySet);
            keys = (String[]) keySet.toArray(new String[0]);
        } else {
            keys = _model.getUrlProperties(url, "COMMENTS");
        }
        if (keys == null) return new String[0];
        String[] fragments = new String[keys.length];
        for (int i=0; i<keys.length; i++) {
            fragments[i] = _store.getFragment(keys[i]);
        }
        return fragments;
    }
    
    /**
     * used by the user interface to access any scripts that have been observed in
     * HTML returned in response to queries for the specified URL
     * @param url the url in question
     * @return the text of any scripts, or a zero length array if there were none
     */    
    public String[] getUrlScripts(HttpUrl url) {
        String[] keys;
        if (url == null) { 
            Set keySet = new HashSet();
            collectUrlProperties(null, "SCRIPTS", keySet);
            keys = (String[]) keySet.toArray(new String[0]);
        } else {
            keys = _model.getUrlProperties(url, "SCRIPTS");
        }
        if (keys == null) return new String[0];
        String[] fragments = new String[keys.length];
        for (int i=0; i<keys.length; i++) {
            fragments[i] = _store.getFragment(keys[i]);
        }
        return fragments;
    }
    
    private void collectUrlProperties(HttpUrl url, String property, Set keyset) {
        int count = _model.getChildUrlCount(url);
        for (int i=0; i<count; i++) {
            HttpUrl child = _model.getChildUrlAt(url, i);
            String[] keys = _model.getUrlProperties(child, property);
            if (keys != null) {
                for (int j=0; j<keys.length; j++) {
                    keyset.add(keys[j]);
                }
            }
            collectUrlProperties(child, property, keyset);
        }
    }
    
    /**
     * used by the user interface to access any comments that have been observed in
     * HTML returned in response to queries for the specified conversation
     * @param id the conversation id
     * @return the text of any comments, or a zero length array if there were none
     */    
    public String[] getConversationComments(ConversationID id) {
        if (id == null) return new String[0];
        String[] keys = _model.getConversationProperties(id, "COMMENTS");
        if (keys == null) return new String[0];
        String[] fragments = new String[keys.length];
        for (int i=0; i<keys.length; i++) {
            fragments[i] = _store.getFragment(keys[i]);
        }
        return fragments;
    }
    
    /**
     * used by the user interface to access any comments that have been observed in
     * HTML returned in response to queries for the specified conversation
     * @param id the conversation id
     * @return the text of any scripts, or a zero length array if there were none
     */    
    public String[] getConversationScripts(ConversationID id) {
        if (id == null) return new String[0];
        String[] keys = _model.getConversationProperties(id, "SCRIPTS");
        if (keys == null) return new String[0];
        String[] fragments = new String[keys.length];
        for (int i=0; i<keys.length; i++) {
            fragments[i] = _store.getFragment(keys[i]);
        }
        return fragments;
    }
    
    /**
     * returns the name of the plugin
     * @return the name of the plugin
     */    
    public String getPluginName() {
        return "Fragments";
    }
    
    /**
     * calls the main loop of the plugin
     */
    public void run() {
        _running = true;
    }
    
    /**
     * stops the plugin running
     * @return true if the plugin could be stopped within a (unspecified) timeout period, false otherwise
     */    
    public boolean stop() {
        _running = false;
        return ! _running;
    }
    
    private void analyse(ConversationID id) {
        HttpUrl url = _model.getUrlOf(id);
        Request request = _model.getRequest(id);
        String cookie = request.getHeader("Cookie");
        if (cookie != null) _model.addConversationProperty(id, "COOKIE", cookie);
        Response response = _model.getResponse(id);
        cookie = response.getHeader("Set-Cookie");
        if (cookie != null) {
            Cookie c = new Cookie(new Date(), cookie);
            _model.addConversationProperty(id, "SET-COOKIE", c.getName() + "=" + c.getValue());
            _model.addUrlProperty(url, "SET-COOKIE", c.getName());
        }
        Object parsed = Parser.parse(url, response);
        if (parsed != null && parsed instanceof NodeList) {
            NodeList nodes = (NodeList) parsed;
            try {
                NodeList comments = nodes.searchFor(RemarkNode.class);
                for (NodeIterator ni = comments.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    String key = Encoding.hashMD5(fragment);
                    int pos = _store.putFragment("COMMENTS", key, fragment);
                    _model.addConversationProperty(id, "COMMENTS", key);
                    _model.addUrlProperty(url, "COMMENTS", key);
                    if (_ui != null) _ui.fragmentAdded(url, id, "COMMENTS", key);
                }
                NodeList scripts = nodes.searchFor(ScriptTag.class);
                for (NodeIterator ni = scripts.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    String key = Encoding.hashMD5(fragment);
                    int pos = _store.putFragment("SCRIPTS", key, fragment);
                    _model.addConversationProperty(id, "SCRIPTS", key);
                    _model.addUrlProperty(url, "SCRIPTS", key);
                    if (_ui != null) _ui.fragmentAdded(url, id, "SCRIPTS", key);
                }
            } catch (ParserException pe) {
                _logger.warning("Looking for fragments, got '" + pe + "'");
            }
        }
        
    }
    
    public void flush() throws StoreException {
        if (_store != null) _store.flush();
    }
    
    public boolean isBusy() {
        return false;
    }
    
    public String getStatus() {
        return _status;
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(ConversationID id) {
            analyse(id);
        }
        
    }
    
}

