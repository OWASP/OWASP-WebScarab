/*
 * FileSystemStore.java
 *
 * Created on August 23, 2003, 4:17 PM
 */

package org.owasp.webscarab.backend;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.model.SiteModelStore;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.URLInfo;

import org.owasp.webscarab.plugin.spider.SpiderStore;
import org.owasp.webscarab.plugin.spider.Link;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;

import java.io.IOException;
import java.io.FileNotFoundException;

import java.util.Set;
import java.util.Iterator;
import java.util.ArrayList;

/**
 *
 * @author  rdawes
 */
public class FileSystemStore implements SiteModelStore, SpiderStore {
    
    private String _dir;
    
    public static boolean isExistingSession(String dir) {
        File f = new File(dir + "conversationlog");
        return f.exists();
    }
    
    /** Creates a new instance of FileSystemStore */
    public FileSystemStore(String dir) {
        if (dir == null) {
            throw new IllegalArgumentException("Cannot create a new FileSystemStore with a null directory!");
        } else {
            _dir = dir;
        }
    }
    
    public void init() throws StoreException {
        if (isExistingSession(_dir)) {
            throw new StoreException(_dir + " contains an existing session already!");
        }
            
        // create the empty directory structure
        File f = new File(_dir);
        if (!f.exists() && !f.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _dir);
        } else if (!f.isDirectory()) {
            throw new StoreException(_dir + " exists, and is not a directory!");
        }
        initSiteModel();
        initSpider();
    }
    
    private void initSiteModel() throws StoreException {
        File f = new File(_dir + "conversations");
        if (!f.exists() && !f.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _dir + "conversations");
        } else if (!f.isDirectory()) {
            throw new StoreException(_dir + "conversations exists, and is not a directory!");
        }
        String log = _dir + "conversationlog";
        f = new File(log);
        try {
            f.createNewFile();
        } catch (IOException ioe) {
            throw new StoreException("Error creating the conversation log : " + ioe);
        }
    }

    private void initSpider() throws StoreException {
        File f = new File(_dir + "spider/");
        if (!f.exists() && !f.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _dir + "spider");
        } else if (!f.isDirectory()) {
            throw new StoreException(_dir + "spider exists, and is not a directory!");
        }
    }
    
    public void writeRequest(String id, Request request) throws StoreException {
        // write the request to the disk using the requests own id
        if (request == null) {
            return;
        }
        try {
            FileOutputStream fos = new FileOutputStream(_dir + "conversations/" + id + "-request");
            request.write(fos);
            fos.close();
        } catch (IOException ioe) {
            throw new StoreException("IOException writing request(" +id + ") : " + ioe);
        }
    }
    
    public Request readRequest(String id) throws StoreException {
        File f = new File(_dir + "conversations/" + id + "-request");
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
        } catch (IOException ioe) {
            throw new StoreException("IOException reading request(" +id + ") : " + ioe);
        }
        return r;
    }
    
    public void writeResponse(String id, Response response) throws StoreException {
        // write the request to the disk using the requests own id
        if (response == null) {
            return;
        }
        try {
            FileOutputStream fos = new FileOutputStream(_dir + "conversations/" + id + "-response");
            response.write(fos);
            fos.close();
        } catch (IOException ioe) {
            throw new StoreException("IOException writing response(" +id + ") : " + ioe);
        }
    }
    
    public Response readResponse(String id) throws StoreException {
        File f = new File(_dir + "conversations/" + id + "-response");
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
        } catch (IOException ioe) {
            throw new StoreException("IOException reading response(" +id + ") : " + ioe);
        }
        return r;
    }
    
    public void writeConversations(Conversation[] conversation) throws StoreException {
        if (conversation == null || conversation.length == 0) {
            return;
        }
        String log = _dir + "conversationlog";
        FileWriter fw;
        try {
            fw = new FileWriter(log);
        } catch (IOException ioe) {
            throw new StoreException("Error creating the conversation log : " + ioe);
        }
        try {
            for (int i=0; i<conversation.length; i++) {
                String id = conversation[i].getProperty("ID");
                if (id == null) {
                    throw new StoreException("Tried to write a conversation with no ID!");
                }
                fw.write("### Conversation : " + id + "\r\n");
                Set keys = conversation[i].keySet();
                Iterator it = keys.iterator();
                String key;
                String value;
                while (it.hasNext()) {
                    key = (String) it.next();
                    value = (String) conversation[i].getProperty(key);
                    if (value == null) value = "";
                    fw.write(key + ": " + value + "\r\n");
                }
                fw.write("\r\n");
            }
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing to conversation Log : " + ioe);
        }
    }
    
    public Conversation[] readConversations() throws StoreException {
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(_dir + "conversationlog"));
        } catch (FileNotFoundException fnfe) {
            throw new StoreException("Conversation log not found! : " + fnfe);
        }
        ArrayList conversations = new ArrayList();
        String line;
        Conversation c = null;
        int index = 0;
        String key;
        String value;
        try {
            while ((line=br.readLine()) != null) {
                if (line.startsWith("### Conversation")) {
                    c = new Conversation();
                } else if (line.equals("")) {
                    conversations.add(c);
                    c = null;
                } else {
                    index = line.indexOf(": ");
                    if (index == -1) {
                        throw new StoreException("Malformed property line while reading conversations :\n" + line);
                    }
                    key = line.substring(0,index);
                    value = line.substring(index+2);
                    if (c == null) {
                        throw new StoreException("Malformed conversation log! No conversation defined before properties");
                    }
                    c.setProperty(key, value);
                }
            }
        } catch (IOException ioe) {
            throw new StoreException("Error reading conversations : " + ioe);
        }
        Conversation[] list = new Conversation[conversations.size()];
        for (int i=0; i<conversations.size(); i++) {
            list[i] = (Conversation) conversations.get(i);
        }
        return list;
    }
    
    public void writeURLInfo(URLInfo[] urlinfo) throws StoreException {
        if (urlinfo == null || urlinfo.length == 0) {
            return;
        }
        String log = _dir + "urlinfo";
        FileWriter fw;
        try {
            fw = new FileWriter(log);
        } catch (IOException ioe) {
            throw new StoreException("Error creating the URLInfo log : " + ioe);
        }
        try {
            for (int i=0; i<urlinfo.length; i++) {
                String url = urlinfo[i].getURL();
                if (url == null) {
                    throw new StoreException("Tried to write an URLInfo with no URL!");
                }
                fw.write("### URL : " + url + "\r\n");
                Set keys = urlinfo[i].keySet();
                Iterator it = keys.iterator();
                String key;
                String value;
                while (it.hasNext()) {
                    key = (String) it.next();
                    value = (String) urlinfo[i].getProperty(key);
                    if (value == null) value = "";
                    fw.write(key + ": " + value + "\r\n");
                }
                fw.write("\r\n");
            }
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing to conversationLog : " + ioe);
        }
    }
    
    public URLInfo[] readURLInfo() throws StoreException {
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(_dir + "urlinfo"));
        } catch (FileNotFoundException fnfe) {
            return new URLInfo[0];
        }
        ArrayList urlinfo = new ArrayList();
        String line;
        URLInfo ui = null;
        int index = 0;
        String url;
        String key;
        String value;
        try {
            while ((line=br.readLine()) != null) {
                if (line.startsWith("### URL :")) {
                    url = line.substring(10);
                    ui = new URLInfo(url);
                } else if (line.equals("")) {
                    urlinfo.add(ui);
                    ui = null;
                } else {
                    index = line.indexOf(": ");
                    if (index == -1) {
                        throw new StoreException("Malformed property line while reading conversations :\n" + line);
                    }
                    key = line.substring(0,index);
                    value = line.substring(index+2);
                    if (ui == null) {
                        throw new StoreException("Malformed URLInfo log! No URLInfo defined before properties");
                    }
                    ui.setProperty(key, value);
                }
            }
            br.close();
        } catch (IOException ioe) {
            throw new StoreException("Error reading URLInfos : " + ioe);
        }
        URLInfo[] list = new URLInfo[urlinfo.size()];
        for (int i=0; i<urlinfo.size(); i++) {
            list[i] = (URLInfo) urlinfo.get(i);
        }
        return list;
    }
    
    public void writeSeenLinks(String[] links) throws StoreException {
        if (links == null || links.length == 0) {
            return;
        }
        String log = _dir + "spider/seenlinks";
        FileWriter fw;
        try {
            fw = new FileWriter(log);
        } catch (IOException ioe) {
            throw new StoreException("Error creating the spider's seenlinks log : " + ioe);
        }
        try {
            for (int i=0; i<links.length; i++) {
                fw.write(links[i] + "\r\n");
            }
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing to spider's seenlinks : " + ioe);
        }
    }
    
    public String[] readSeenLinks() throws StoreException {
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(_dir + "spider/seenlinks"));
        } catch (FileNotFoundException fnfe) {
            return new String[0];
        }
        ArrayList seen = new ArrayList();
        String line;
        try {
            while ((line=br.readLine()) != null) {
                seen.add(line);
            }
            br.close();
        } catch (IOException ioe) {
            throw new StoreException("Error reading spider/seenlinks : " + ioe);
        }
        String[] list = new String[seen.size()];
        for (int i=0; i<seen.size(); i++) {
            list[i] = (String) seen.get(i);
        }
        return list;
    }
    
    public void writeUnseenLinks(Link[] links) throws StoreException {
        if (links == null || links.length == 0) {
            return;
        }
        String log = _dir + "spider/unseenlinks";
        FileWriter fw;
        try {
            fw = new FileWriter(log);
        } catch (IOException ioe) {
            throw new StoreException("Error creating the spider's unseenlinks log : " + ioe);
        }
        String type;
        try {
            for (int i=0; i<links.length; i++) {
                fw.write(links[i].getURL() + "\r\n");
                fw.write(links[i].getReferer() + "\r\n");
                type = links[i].getType();
                if (type != null) {
                    fw.write(type + "\r\n");
                }
                fw.write("\r\n");
            }
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            throw new StoreException("Error writing to spider's unseenlinks : " + ioe);
        }
    }
    
    public Link[] readUnseenLinks() throws StoreException {
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(_dir + "spider/unseenlinks"));
        } catch (FileNotFoundException fnfe) {
            return new Link[0];
        }
        ArrayList unseen = new ArrayList();
        String url;
        String referer;
        String type = null;
        Link link = null;
        try {
            while ((url=br.readLine()) != null) {
                referer=br.readLine();
                link = new Link(url, referer);
                type = br.readLine();
                if (type.equals("")) {
                    unseen.add(link);
                } else {
                    link.setType(type);
                    unseen.add(link);
                    br.readLine();
                }
            }
            br.close();
        } catch (IOException ioe) {
            throw new StoreException("Error reading spider/unseenlinks : " + ioe);
        }
        Link[] list = new Link[unseen.size()];
        for (int i=0; i<unseen.size(); i++) {
            list[i] = (Link) unseen.get(i);
        }
        return list;
    }
    
    public static void main(String[] args) {
        FileSystemStore fss = new FileSystemStore("/tmp/webscarab/");
        try {
            Request req = fss.readRequest("1");
            Request req2 = new Request(req);
            System.out.println("Request is '" + req.toString() + "'");
            System.out.println("Request2 is '" + req2.toString() + "'");
        } catch (Exception e) {
            System.out.println("Exception : " + e);
        }
    }

}