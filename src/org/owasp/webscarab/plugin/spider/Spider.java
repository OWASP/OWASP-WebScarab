/*
 * Spider.java
 *
 * Created on August 5, 2003, 10:52 PM
 */

package org.owasp.webscarab.plugin.spider;

import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;

import org.owasp.webscarab.plugin.Plug;
import org.owasp.webscarab.plugin.AbstractWebScarabPlugin;

import org.htmlparser.Node;

import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.CompositeTag;

import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

import java.util.logging.Logger;

/**
 *
 * @author  rdawes
 */

public class Spider extends AbstractWebScarabPlugin {
    
    private Plug _plug;
    private Logger _logger = Logger.getLogger("Plug.Spider");
    
    /** Creates a new instance of Spider */
    public Spider(Plug plug) {
        _plug = plug;
        _logger.info("Spider initialised");
    }
    
    public String getPluginName() {
        return new String("Spider");
    }
    
    /** Called by the WebScarab data model once the {@link Response} has been parsed. It
     * is called for all Conversations seen by the model (submitted by all plugins, not
     * just this one).
     * Any information gathered by this module should also be summarised into the
     * supplied URLInfo, since only this analysis procedure will know how to do so!
     * @param conversation The parsed Conversation to be analysed.
     * @param urlinfo The class instance that contains the summarised information about this
     * particular URL
     */
    public void analyse(Conversation conversation, URLInfo urlinfo) {
        _logger.info("Spider analyse");
        NodeList nodelist = conversation.getNodeList();
        if (nodelist == null) return;
        _logger.info("NodeList has " + nodelist.size() + " elements");
        recurseNodes(nodelist);
    }
    
    private void recurseNodes(NodeList nodelist) {
        try {
            for (NodeIterator ni = nodelist.elements(); ni.hasMoreNodes();) {
                Node node = ni.nextNode();
                if (node instanceof LinkTag) {
                    LinkTag linkTag = (LinkTag) node;
                    System.out.println(linkTag.getLink());
                } else if (node instanceof CompositeTag) {
                    CompositeTag ctag = (CompositeTag) node;
                    recurseNodes(ctag.getChildren());
                } else {
                    // _logger.info("Node was a " + node.getClass());
                }
            }
        } catch (ParserException pe) {
            _logger.severe("ParserException : " + pe);
        }
    }        
    
}
