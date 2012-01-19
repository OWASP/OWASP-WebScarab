/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

/*
 * Fragments.java
 *
 * Created on August 25, 2004, 10:45 PM
 */

package org.owasp.webscarab.plugin.fragments;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.htmlparser.nodes.RemarkNode;
import org.htmlparser.tags.FormTag;
import org.htmlparser.tags.InputTag;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;
import org.owasp.webscarab.model.ConversationID;
import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.parser.Parser;
import org.owasp.webscarab.plugin.Framework;
import org.owasp.webscarab.plugin.Hook;
import org.owasp.webscarab.plugin.Plugin;

/**
 * This plugin looks for comments and scripts in the source of HTML pages.
 * @author knoppix
 */
public class Fragments implements Plugin {
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private FragmentsModel _model = null;
	/**
	 * Pattern that searches for window.location in right-hand side assignments.
	 * Can trap potential DOM-based xss These ones search for 
	 * window.location,
	 * window.top.location document.URL document.location document.URLUnencoded
	 */
	Pattern[] jsDomXssPatterns = {
			//This one searches for 
			// fobobar = window.location
			// baz = window.top.location
			
			Pattern.compile("[\\S&&[^=]]+\\s*=\\s*window\\.(?:top\\.)?location"),
			//This one searches for 
			// foo= document.URL
			// bar = document.URLUnencoded
			// gazonk = document.location
			Pattern
					.compile("[\\S&&[^=]]+\\s*=\\s*document\\.(?:URL|URLUnencoded|location)"), 
			
			//This one searches for string concatenation
			// such as a = "<img src='"+document.URL+"/foobar' />";
			Pattern.compile("\\+\\s*window\\.(?:top\\.)?location"),
			Pattern.compile("\\+\\s*document\\.(?:URL|URLUnencoded|location)"),
	};
	
	Pattern[] jsDomXssFalsePositivesPattern = {
		//This one removes false positives on the form
			// if(blaha != window.location)
			// if(blaha == document.URL)
			Pattern.compile(".+[!=]+=.*(?:document|window)"),
			//This one removes 
			// + escape(document.location)
			//which normally is not a problem
			Pattern.compile("escape\\((?:document.|window.).+\\)"),
	};
	
    /**
     * Creates a new instance of Fragments
     * @param props contains the user's configuration properties
     */
    public Fragments(Framework framework) {
        _model = new FragmentsModel(framework.getModel());
    }
    
    public FragmentsModel getModel() {
        return _model;
    }
    
    /**
     * Sets the store that this plugin uses
     * @param session the new session
     */    
    public void setSession(String type, Object store, String session) throws StoreException {
        if (type.equals("FileSystem") && (store instanceof File)) {
            _model.setStore(new FileSystemStore((File) store, session));
        } else {
            throw new StoreException("Store type '" + type + "' is not supported in " + getClass().getName());
        }
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
        _model.setRunning(true);
    }
    
    /**
     * stops the plugin running
     * @return true if the plugin could be stopped within a (unspecified) timeout period, false otherwise
     */    
    public boolean stop() {
        _model.setRunning(false);
        return ! _model.isRunning();
    }
    
    public void analyse(ConversationID id, Request request, Response response, String origin) {
        HttpUrl url = request.getURL();
        Object parsed = Parser.parse(url, response);
        if (parsed != null && parsed instanceof NodeList) {
            NodeList nodes = (NodeList) parsed;
            try {
                NodeList comments = nodes.searchFor(RemarkNode.class);
                NodeList scripts = nodes.searchFor(ScriptTag.class);
                NodeList forms = nodes.searchFor(FormTag.class);
                NodeList inputs = nodes.searchFor(InputTag.class);
            
                for (NodeIterator ni = comments.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    _model.addFragment(url, id, FragmentsModel.KEY_COMMENTS, fragment);
                }
                for (NodeIterator ni = scripts.elements(); ni.hasMoreNodes(); ) {
                    String fragment = ni.nextNode().toHtml();
                    _model.addFragment(url, id, FragmentsModel.KEY_SCRIPTS, fragment);
                }
                for (NodeIterator ni = forms.elements(); ni.hasMoreNodes(); ) {
                	FormTag form = (FormTag) ni.nextNode();
                	String fragment = "action:"+form.getAttribute("action")+" method:"+form.getAttribute("method");
                	_model.addFragment(url, id, FragmentsModel.KEY_FORMS,fragment );
                }
                for (NodeIterator ni = inputs.elements(); ni.hasMoreNodes(); ) {
                	InputTag tag = (InputTag) ni.nextNode();
                	String type = tag.getAttribute("type");
                	if( "hidden".equals(type))
                	{
                		String fragment = tag.toHtml();
                		_model.addFragment(url, id, FragmentsModel.KEY_HIDDENFIELD, fragment);
                	}
                	if("file".equals(type))
                	{
                		String fragment = tag.toHtml();
                		_model.addFragment(url, id, FragmentsModel.KEY_FILEUPLOAD, fragment);
                	}
                }
            } catch (ParserException pe) {
                _logger.warning("Looking for fragments, got '" + pe + "'");
            }
        }
        //Now, look for "dangerous" javascript
        try {
			String content = new String(response.getContent(),"UTF-8");
			for (int i = 0; i < jsDomXssPatterns.length; i++) {
				Matcher m = jsDomXssPatterns[i].matcher(content);
				while(m.find())
				{
					String fragment = m.group();
					boolean falsePositive = false;
					//Test false positives
					for (int j = 0; j < jsDomXssFalsePositivesPattern.length; j++) {
						Matcher fp = jsDomXssFalsePositivesPattern[j]
								.matcher(fragment);
						if (fp.find()) {
							falsePositive = true;
							_logger
									.info("Ignoring XSS-DOM fragment '"
											+ fragment
											+ "' - false positive according to pattern :"
											+ jsDomXssFalsePositivesPattern[j]
													.pattern());
							break;
						}
					}
					if (!falsePositive)
					{
						_model.addFragment(url, id, FragmentsModel.KEY_DOMXSS,
								fragment);
					}
					
				}
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
    }
    public void flush() throws StoreException {
        _model.flush();
    }
    
    public boolean isBusy() {
        return _model.isBusy();
    }
    
    public String getStatus() {
        return _model.getStatus();
    }
    
    public boolean isModified() {
        return _model.isModified();
    }
    
    public boolean isRunning() {
        return _model.isRunning();
    }
    
    public Object getScriptableObject() {
        return null;
    }
    
    public Hook[] getScriptingHooks() {
        return new Hook[0];
    }
    
}

