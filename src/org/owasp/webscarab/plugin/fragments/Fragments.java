/*
 * Fragments.java
 *
 * Created on August 25, 2004, 10:45 PM
 */

package org.owasp.webscarab.plugin.fragments;

import java.io.File;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

import org.htmlparser.RemarkNode;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.SiteModel;
import org.owasp.webscarab.model.SiteModelAdapter;
import org.owasp.webscarab.parser.Parser;
import org.owasp.webscarab.plugin.Plugin;

/**
 * This plugin looks for comments and scripts in the source of HTML pages.
 * @author knoppix
 */
public class Fragments extends Plugin {
    
    private Thread _runThread = null;
    
    private LinkedList _queue = new LinkedList();
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private boolean _stopping = false;
    private Listener _listener = null;
    
    private SiteModel _model = null;
    
    private FragmentsStore _store = null;
    
    private String _status = "Stopped";
    
    /**
     * Creates a new instance of Fragments
     * @param props contains the user's configuration properties
     */
    public Fragments(Properties props) {
        super(props);
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
        _runThread = Thread.currentThread();
        _stopping = false;
        _running = true;
        _status = "Started";
        // if (_ui != null) _ui.setEnabled(_running);
        while (!_stopping) {
            ConversationID id = null;
            if (_queue.size() > 0) { 
                id = (ConversationID) _queue.removeFirst();
                _status = "Analysing " + id + ", " + _queue.size() + " remaining";
                analyse(id);
            } else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {}
                _status = "Started, Idle";
            }
        }
        _running = false;
        _runThread = null;
        // if (_ui != null) _ui.setEnabled(_running);
        _status = "Stopped";
    }
    
    /**
     * stops the plugin running
     * @return true if the plugin could be stopped within a (unspecified) timeout period, false otherwise
     */    
    public boolean stop() {
        if (isBusy()) return false;
        _stopping = true;
        try {
            _runThread.join(5000);
        } catch (InterruptedException ie) {
            _logger.warning("Interrupted!");
        }
        return !_running;
    }
    
    private void analyse(ConversationID id) {
        HttpUrl url = _model.getUrlOf(id);
        Response response = _model.getResponse(id);
        Object parsed = Parser.parse(url, response);
        if (parsed != null && parsed instanceof NodeList) {
            NodeList nodes = (NodeList) parsed;
            try {
                NodeList comments = nodes.searchFor(RemarkNode.class);
                for (NodeIterator ni = comments.elements(); ni.hasMoreNodes(); ) {
                    String key = _store.putFragment(ni.nextNode().toHtml());
                    _model.addConversationProperty(id, "COMMENTS", key);
                    _model.addUrlProperty(url, "COMMENTS", key);
                }
                NodeList scripts = nodes.searchFor(ScriptTag.class);
                for (NodeIterator ni = scripts.elements(); ni.hasMoreNodes(); ) {
                    String key = _store.putFragment(ni.nextNode().toHtml());
                    _model.addConversationProperty(id, "SCRIPTS", key);
                    _model.addUrlProperty(url, "SCRIPTS", key);
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
        return _queue.size() > 0;
    }
    
    public String getStatus() {
        return _status;
    }
    
    private class Listener extends SiteModelAdapter {
        
        public void conversationAdded(ConversationID id) {
            // queue it for checking
            synchronized(_queue) {
                _queue.addLast(id);
            }
        }
        
    }
    
}

