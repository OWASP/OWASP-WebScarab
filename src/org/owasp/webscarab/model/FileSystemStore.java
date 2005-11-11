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
 * FileSystemStore.java
 *
 * Created on August 23, 2003, 4:17 PM
 */

package org.owasp.webscarab.model;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
// import java.text.ParseException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.owasp.webscarab.util.MRUCache;

/**
 *
 * @author  rdawes
 */
public class FileSystemStore implements SiteModelStore {
    
    private static final HttpUrl[] NO_CHILDREN = new HttpUrl[0];
    
    private File _dir;
    private File _conversationDir;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    private List _conversations = new ArrayList();
    private SortedMap _conversationProperties = new TreeMap(new NullComparator());
    private SortedMap _urlProperties = new TreeMap(new NullComparator());
    
    private SortedMap _urlConversations = new TreeMap(new NullComparator());
    private SortedMap _urls = new TreeMap(new NullComparator());
    
    private Map _requestCache = new MRUCache(16);
    private Map _responseCache = new MRUCache(16);
    private Map _urlCache = new MRUCache(32);
    
    private SortedMap _cookies = new TreeMap();
    
    public static boolean isExistingSession(File dir) {
        File f = new File(dir, "conversations");
        return f.exists() && f.isDirectory();
    }
    
    /** Creates a new instance of FileSystemStore */
    public FileSystemStore(File dir) throws StoreException {
        _logger.setLevel(Level.FINE);
        if (dir == null) {
            throw new StoreException("Cannot create a new FileSystemStore with a null directory!");
        } else {
            _dir = dir;
        }
        _conversationDir = new File(_dir, "conversations");
        if (_conversationDir.exists()) {
            _logger.fine("Loading session from " + _dir);
            load();
            _logger.fine("Finished loading session from " + _dir);
        } else {
            create();
        }
    }
    
    private void load() throws StoreException {
        _logger.fine("Loading conversations");
        loadConversationProperties();
        _logger.fine("Loading urls");
        loadUrlProperties();
        _logger.fine("Loading cookies");
        loadCookies();
        _logger.fine("Done!");
    }
    
    private void loadConversationProperties() throws StoreException {
        ConversationID.reset();
        try {
            File f = new File(_dir, "conversationlog");
            if (!f.exists()) return;
            BufferedReader br = new BufferedReader(new FileReader(f));
            int linecount = 0;
            String line;
            Map map = null;
            ConversationID id = null;
            while ((line = br.readLine()) != null) {
                linecount++;
                if (line.startsWith("### Conversation :")) {
                    String cid = line.substring(line.indexOf(":")+2);
                    try {
                        id = new ConversationID(cid);
                        map = new HashMap();
                        _conversations.add(id);
                        _conversationProperties.put(id, map);
                    } catch (NumberFormatException nfe) {
                        throw new StoreException("Malformed conversation ID (" + cid +") parsing conversation log");
                    }
                } else if (line.equals("")) {
                    try {
                        HttpUrl url = new HttpUrl((String) map.get("URL"));
                        addConversationForUrl(url, id);
                    } catch (MalformedURLException mue) {
                        throw new StoreException("Malformed URL reading conversation " + id);
                    }
                    id = null;
                    map = null;
                } else {
                    if (map == null) throw new StoreException("Malformed conversation log at line " + linecount);
                    String property = line.substring(0, line.indexOf(":"));
                    String value = line.substring(line.indexOf(":")+2);
                    addProperty(map, property, value);
                }
            }
        } catch (IOException ioe) {
            throw new StoreException("Exception loading conversationlog: " + ioe);
        }
    }
    
    private void loadUrlProperties() throws StoreException {
        try {
            File f = new File(_dir, "urlinfo");
            if (!f.exists()) return;
            BufferedReader br = new BufferedReader(new FileReader(f));
            int linecount = 0;
            String line;
            Map map = null;
            HttpUrl url = null;
            while ((line = br.readLine()) != null) {
                linecount++;
                if (line.startsWith("### URL :")) {
                    String urlstr = line.substring(line.indexOf(":")+2);
                    try {
                        url = new HttpUrl(urlstr);
                        addUrl(url);
                        map = (Map) _urlProperties.get(url);
                    } catch (MalformedURLException mue) {
                        throw new StoreException("Malformed URL " + urlstr + " at line " + linecount + " in urlinfo");
                    }
                } else if (line.equals("")) {
                    url = null;
                    map = null;
                } else {
                    if (map == null) throw new StoreException("Malformed url info at line " + linecount);
                    String property = line.substring(0, line.indexOf(":"));
                    String value = line.substring(line.indexOf(":")+2);
                    addProperty(map, property, value);
                }
            }
        } catch (IOException ioe) {
            throw new StoreException("Exception loading url info : " + ioe);
        }
    }
    
    private void create() throws StoreException {
        // create the empty directory structure
        if (!_dir.exists() && !_dir.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _dir);
        } else if (!_dir.isDirectory()) {
            throw new StoreException(_dir + " exists, and is not a directory!");
        }
        
        _conversationDir = new File(_dir, "conversations");
        if (!_conversationDir.exists() && !_conversationDir.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _conversationDir);
        } else if (!_conversationDir.isDirectory()) {
            throw new StoreException(_conversationDir + " exists, and is not a directory!");
        }
        
    }
    
    /**************************************************************************
     * The implementation of the SiteModelStore interface                     *
     **************************************************************************/
    
    /**
     * adds a new conversation
     * @param id the id of the new conversation
     * @param when the date the conversation was created
     * @param request the request to add
     * @param response the response to add
     */
    public int addConversation(ConversationID id, Date when, Request request, Response response) {
        setRequest(id, request);
        setResponse(id, response);
        Map map = new HashMap();
        _conversationProperties.put(id, map);
        setConversationProperty(id, "METHOD", request.getMethod());
        setConversationProperty(id, "URL", request.getURL().toString());
        setConversationProperty(id, "STATUS", response.getStatusLine());
        setConversationProperty(id, "WHEN", Long.toString(when.getTime()));
        
        addConversationForUrl(request.getURL(), id);
        int index = Collections.binarySearch(_conversations, id);
        if (index<0) {
            index = -index -1;
            _conversations.add(index, id);
        }
        return index;
    }
    
    private void addConversationForUrl(HttpUrl url, ConversationID id) {
        List clist = (List) _urlConversations.get(url);
        if (clist == null) {
            clist = new ArrayList();
            _urlConversations.put(url, clist);
        }
        int index = Collections.binarySearch(clist, id);
        if (index < 0)
            clist.add(-index-1, id);
    }
    
    /**
     * sets a value for a property, for a specific conversation
     * @param id the conversation ID
     * @param property the name of the property
     * @param value the value to set
     */
    public void setConversationProperty(ConversationID id, String property, String value) {
        Map map = (Map) _conversationProperties.get(id);
        if (map == null) throw new NullPointerException("No conversation Map for " + id);
        map.put(property, value);
    }
    
    /**
     * adds a new value to the list of values for the specified property and conversation
     * @param id the conversation id
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addConversationProperty(ConversationID id, String property, String value) {
        Map map = (Map) _conversationProperties.get(id);
        if (map == null) throw new NullPointerException("No conversation Map for " + id);
        return addProperty(map, property, value);
    }
    
    private boolean addProperty(Map map, String property, String value) {
        Object previous = map.get(property);
        if (previous == null) {
            map.put(property, value);
            return true;
        } else if (previous instanceof String) {
            if (previous.equals(value)) return false;
            String[] newval = new String[2];
            newval[0] = (String) previous;
            newval[1] = value;
            map.put(property, newval);
            return true;
        } else {
            String[] old = (String[]) previous;
            for (int i=0; i<old.length; i++)
                if (old[i].equals(value))
                    return false;
            String[] newval = new String[old.length + 1];
            System.arraycopy(old, 0, newval, 0, old.length);
            newval[old.length] = value;
            map.put(property, newval);
            return true;
        }
    }
    
    /**
     * returns an array of strings containing the values that have been set for the
     * specified conversation property
     * @param id the conversation id
     * @param property the name of the property
     * @return the property values
     */
    public String[] getConversationProperties(ConversationID id, String property) {
        Map map = (Map) _conversationProperties.get(id);
        if (map == null) throw new NullPointerException("No conversation Map for " + id);
        return getProperties(map, property);
    }
    
    private String[] getProperties(Map map, String property) {
        Object value = map.get(property);
        if (value == null) {
            return new String[0];
        } else if (value instanceof String[]) {
            String[] values = (String[]) value;
            if (values.length == 0) return values;
            String[] copy = new String[values.length];
            System.arraycopy(values, 0, copy, 0, values.length);
            return copy;
        } else {
            String[] values = new String[] {(String) value};
            return values;
        }
    }
    
    /**
     * adds an entry for the specified URL, so that subsequent calls to isKnownUrl will
     * return true.
     * @param url the url to add
     */
    public void addUrl(HttpUrl url) {
        if (_urlProperties.get(url) != null) throw new IllegalStateException("Adding an URL that is already there " + url);
        Map map = new HashMap();
        _urlProperties.put(url, map);
        
        HttpUrl parent = url.getParentUrl();
        _urlCache.remove(parent);
        SortedSet childSet = (SortedSet) _urls.get(parent);
        if (childSet == null) {
            childSet = new TreeSet();
            _urls.put(parent, childSet);
        }
        childSet.add(url);
    }
    
    /**
     * returns true if the url is already existing in the store, false otherwise
     * @param url the url to test
     * @return true if the url is already known, false otherwise
     */
    public boolean isKnownUrl(HttpUrl url) {
        return _urlProperties.containsKey(url);
    }
    
    /**
     * sets a value for a property, for a specific URL
     * @param url the url
     * @param property the name of the property
     * @param value the value to set
     */
    public void setUrlProperty(HttpUrl url, String property, String value) {
        Map map = (Map) _urlProperties.get(url);
        if (map == null) throw new NullPointerException("No URL Map for " + url);
        map.put(property, value);
    }
    
    /**
     * adds a new value to the list of values for the specified property and url
     * @param url the url
     * @param property the name of the property
     * @param value the value to add
     */
    public boolean addUrlProperty(HttpUrl url, String property, String value) {
        Map map = (Map) _urlProperties.get(url);
        if (map == null) throw new NullPointerException("No URL Map for " + url);
        return addProperty(map, property, value);
    }
    
    /**
     * returns an array of strings containing the values that have been set for the
     * specified url property
     * @param url the url
     * @param property the name of the property
     * @return the property values
     */
    public String[] getUrlProperties(HttpUrl url, String property) {
        Map map = (Map) _urlProperties.get(url);
        if (map == null) return new String[0];
        return getProperties(map, property);
    }
    
    /**
     * returns the number of URL's that are children of the URL passed.
     * @param url the url
     * @return the number of children of the supplied url.
     */
    public int getChildCount(HttpUrl url) {
        SortedSet childSet = (SortedSet) _urls.get(url);
        if (childSet == null) return 0;
        return childSet.size();
    }
    
    /**
     * returns the specified child of the URL passed.
     * @param url the url
     * @param index the index
     * @return the child at position index.
     */
    public HttpUrl getChildAt(HttpUrl url, int index) {
        HttpUrl[] children = (HttpUrl[]) _urlCache.get(url);
        if (children == null) {
            SortedSet childSet = (SortedSet) _urls.get(url);
            if (childSet == null)
                throw new IndexOutOfBoundsException(url + " has no children");
            if (index >= childSet.size())
                throw new IndexOutOfBoundsException(url + " has only " + childSet.size() + " children, not " + index);
            children = ((HttpUrl[]) childSet.toArray(NO_CHILDREN));
            _urlCache.put(url, children);
        }
        return children[index];
    }
    
    public int getIndexOf(HttpUrl url) {
        HttpUrl parent = url.getParentUrl();
        HttpUrl[] children = (HttpUrl[]) _urlCache.get(parent);
        if (children == null) {
            SortedSet childSet = (SortedSet) _urls.get(parent);
            if (childSet == null)
                throw new IndexOutOfBoundsException(url + " has no children");
            children = ((HttpUrl[]) childSet.toArray(NO_CHILDREN));
            _urlCache.put(parent, children);
        }
        return Arrays.binarySearch(children, url);
    }
    
    /**
     * returns the number of conversations related to the url supplied
     * @param url the url in question, or null for all conversations
     * @return the number of conversations related to the supplied URL
     */
    public int getConversationCount(HttpUrl url) {
        if (url == null) return _conversationProperties.size();
        List list = (List) _urlConversations.get(url);
        if (list == null) return 0;
        return list.size();
    }
    
    /**
     * returns the ID of the conversation at position index in the list of conversations
     * related to the supplied url. If url is null, returns the position in the total
     * list of conversations.
     * @param url the url to use as a filter, or null for none
     * @param index the position in the list
     * @return the conversation id
     */
    public ConversationID getConversationAt(HttpUrl url, int index) {
        List list;
        if (url == null) {
            list = new ArrayList(_conversationProperties.keySet());
        } else {
            list = (List) _urlConversations.get(url);
        }
        if (list == null) throw new NullPointerException(url + " does not have any conversations");
        if (list.size() < index) throw new ArrayIndexOutOfBoundsException(url + " does not have " + index + " conversations");
        return (ConversationID) list.get(index);
    }
    
    /**
     * Conversations are sorted according to the natural ordering of their conversationID.
     * This method returns the position of the specified conversation in the list of conversations
     * relating to the specified URL. If the URL is null, returns the position of the conversation
     * in the overall list of conversations.
     * @param url acts as a filter on the overall list of conversations
     * @param id the conversation
     * @return the position in the list, or the insertion point if it is not in the list
     */
    public int getIndexOfConversation(HttpUrl url, ConversationID id) {
        List list;
        if (url == null) {
            list = _conversations;
        } else {
            list = (List) _urlConversations.get(url);
        }
        if (list == null) throw new NullPointerException(url + " has no conversations");
        int index =  Collections.binarySearch(list, id);
        return index;
    }
    
    /**
     * associates the specified request with the provided conversation id
     * @param id the conversation id
     * @param request the request
     */
    public void setRequest(ConversationID id, Request request) {
        // write the request to the disk using the requests own id
        if (request == null) {
            return;
        }
        _requestCache.put(id, request);
        try {
            File f = new File(_conversationDir, id + "-request");
            FileOutputStream fos = new FileOutputStream(f);
            request.write(fos);
            fos.close();
        } catch (IOException ioe) {
            _logger.severe("IOException writing request(" +id + ") : " + ioe);
        }
    }
    
    /*
     * retrieves the request associated with the specified conversation id
     */
    public Request getRequest(ConversationID id) {
        Object o = _requestCache.get(id);
        if (o != null) return (Request) o;
        
        File f = new File(_conversationDir, id + "-request");
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException fnfe) {
            return null;
        }
        Request r = new Request();
        try {
            r.read(fis);
            r.getContent();
            fis.close();
            return r;
        } catch (IOException ioe) {
            _logger.severe("IOException reading request(" +id + ") : " + ioe);
            return null;
        }
    }
    
    /**
     * associates the response with the specified conversation id
     * @param id the conversation id
     * @param response the response
     */
    public void setResponse(ConversationID id, Response response) {
        // write the request to the disk using the requests own id
        if (response == null) {
            return;
        }
        _responseCache.put(id, response);
        try {
            File f = new File(_conversationDir, id + "-response");
            FileOutputStream fos = new FileOutputStream(f);
            response.write(fos);
            fos.close();
        } catch (IOException ioe) {
            _logger.severe("IOException writing response(" +id + ") : " + ioe);
        }
    }
    
    /*
     * retrieves the response associated with the specified conversation id
     */
    public Response getResponse(ConversationID id) {
        Object o = _responseCache.get(id);
        if (o != null) return (Response) o;
        
        File f = new File(_conversationDir, id + "-response");
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
        } catch (FileNotFoundException fnfe) {
            return null;
        }
        Response r = new Response();
        try {
            r.read(fis);
            r.getContent();
            fis.close();
            return r;
        } catch (IOException ioe) {
            _logger.severe("IOException reading response(" +id + ") : " + ioe);
            return null;
        }
    }
    
    public void flush() throws StoreException {
        flushConversationProperties();
        flushUrlProperties();
        flushCookies();
    }
    
    private void flushConversationProperties() throws StoreException {
        try {
            File f = new File(_dir, "conversationlog");
            BufferedWriter bw = new BufferedWriter(new FileWriter(f));
            Iterator it = _conversationProperties.keySet().iterator();
            ConversationID id;
            Map map;
            while (it.hasNext()) {
                id = (ConversationID) it.next();
                map = (Map) _conversationProperties.get(id);
                bw.write("### Conversation : " + id + "\n");
                Iterator props = map.keySet().iterator();
                while(props.hasNext()) {
                    String property = (String) props.next();
                    String[] values = getProperties(map,  property);
                    if (values != null && values.length > 0) {
                        for (int i=0; i< values.length; i++) {
                            bw.write(property + ": " + values[i] + "\n");
                        }
                    }
                }
                bw.write("\n");
            }
            bw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing conversation properties: " + ioe);
        }
    }
    
    private void flushUrlProperties() throws StoreException {
        try {
            File f = new File(_dir, "urlinfo");
            BufferedWriter bw = new BufferedWriter(new FileWriter(f));
            Iterator it = _urlProperties.keySet().iterator();
            HttpUrl url;
            Map map;
            while (it.hasNext()) {
                url = (HttpUrl) it.next();
                map = (Map) _urlProperties.get(url);
                bw.write("### URL : " + url + "\n");
                Iterator props = map.keySet().iterator();
                while(props.hasNext()) {
                    String property = (String) props.next();
                    String[] values = getProperties(map,  property);
                    if (values != null && values.length > 0) {
                        for (int i=0; i< values.length; i++) {
                            bw.write(property + ": " + values[i] + "\n");
                        }
                    }
                }
                bw.write("\n");
            }
            bw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing url properties: " + ioe);
        }
    }
    
    public int getCookieCount() {
        return _cookies.size();
    }
    
    public int getCookieCount(String key) {
        List list = (List) _cookies.get(key);
        if (list == null) return 0;
        return list.size();
    }
    
    public String getCookieAt(int index) {
        return (String) new ArrayList(_cookies.keySet()).get(index);
    }
    
    public Cookie getCookieAt(String key, int index) {
        List list = (List) _cookies.get(key);
        if (list == null) throw new NullPointerException("No such cookie! " + key);
        return (Cookie) list.get(index);
    }
    
    public Cookie getCurrentCookie(String key) {
        List list = (List) _cookies.get(key);
        if (list == null) throw new NullPointerException("No such cookie! " + key);
        return (Cookie) list.get(list.size()-1);
    }
    
    public int getIndexOfCookie(Cookie cookie) {
        return new ArrayList(_cookies.keySet()).indexOf(cookie.getKey());
    }
    
    public int getIndexOfCookie(String key, Cookie cookie) {
        List list = (List) _cookies.get(key);
        if (list == null) throw new NullPointerException("No such cookie! " + key);
        return list.indexOf(cookie);
    }
    
    /**
     * adds a new cookie to the store
     * @param cookie the cookie to add
     * @return true if the cookie did not previously exist in the store, false if it did.
     */
    public boolean addCookie(Cookie cookie) {
        String key = cookie.getKey();
        List list = (List) _cookies.get(key);
        if (list == null) {
            list = new ArrayList();
            _cookies.put(key, list);
        }
        if (list.indexOf(cookie) > -1) return false;
        list.add(cookie);
        return true;
    }
    
    /**
     * removes a cookie from the store
     * @return true if the cookie was deleted, or false if it was not already in the store
     * @param cookie the cookie to remove
     */
    public boolean removeCookie(Cookie cookie) {
        String key = cookie.getKey();
        List list = (List) _cookies.get(key);
        if (list == null) return false;
        boolean deleted = list.remove(cookie);
        if (list.size() == 0) _cookies.remove(key);
        return deleted;
    }
    
    private void loadCookies() throws StoreException {
        _cookies.clear();
        try {
            File f = new File(_dir, "cookies");
            if (!f.exists()) return;
            BufferedReader br = new BufferedReader(new FileReader(f));
            int linecount = 0;
            String line;
            List list = null;
            String name = null;
            Cookie cookie = null;
            while ((line = br.readLine()) != null) {
                linecount++;
                if (line.startsWith("### Cookie :")) {
                    name = line.substring(line.indexOf(":")+2);
                    list = new ArrayList();
                    _cookies.put(name, list);
                } else if (line.equals("")) {
                    name = null;
                    list = null;
                } else {
                    if (list == null) throw new StoreException("Malformed cookie log at line " + linecount);
                    int pos = line.indexOf(" ");
                    try {
                        long time = Long.parseLong(line.substring(0, pos));
                        cookie = new Cookie(new Date(time), line.substring(pos+1));
                        list.add(cookie);
                    } catch (Exception e) {
                        throw new StoreException("Malformed cookie log at line " + linecount + " : " + e);
                    }
                }
            }
        } catch (IOException ioe) {
            throw new StoreException("Exception loading conversationlog: " + ioe);
        }
    }
    
    private void flushCookies() throws StoreException {
        try {
            File f = new File(_dir, "cookies");
            BufferedWriter bw = new BufferedWriter(new FileWriter(f));
            Iterator it = _cookies.keySet().iterator();
            String name;
            List list;
            while (it.hasNext()) {
                name = (String) it.next();
                list = (List) _cookies.get(name);
                bw.write("### Cookie : " + name + "\n");
                Iterator cookies = list.iterator();
                while(cookies.hasNext()) {
                    Cookie cookie = (Cookie) cookies.next();
                    bw.write(cookie.toString() + "\n");
                }
                bw.write("\n");
            }
            bw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing cookies: " + ioe);
        }
    }
    
    private class NullComparator implements Comparator {
        
        public int compare(Object o1, Object o2) {
            if (o1 == null && o2 == null) return 0;
            if (o1 == null && o2 != null) return 1;
            if (o1 != null && o2 == null) return -1;
            if (o1 instanceof Comparable) return ((Comparable)o1).compareTo(o2);
            throw new ClassCastException("Incomparable objects " + o1.getClass().getName() + " and " + o2.getClass().getName());
        }
        
    }
    
}
