/*
 * CookieJar.java
 *
 * Created on September 10, 2003, 11:44 PM
 */

package org.owasp.webscarab.model;

import org.owasp.util.DateUtil;

import java.util.TreeMap;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Date;
import java.text.ParseException;

import java.net.URL;
import java.net.MalformedURLException;

import javax.swing.DefaultListModel;

/** This class serves as a repository and parser of Cookies seen in Responses.
 * It also provides methods for populating a Request with the appropriate Cookies
 * for the Request domain and path.
 * @author rdawes
 */

public class CookieJar {
    
    private TreeMap _cookies = new TreeMap();
    private DefaultListModel _cookieList = new DefaultListModel();
    
    /** Creates a new instance of CookieJar */
    public CookieJar() {
    }
    
    public void clear() {
        _cookies.clear();
        _cookieList.removeAllElements();
    }
    
    /** Looks in the headers of the supplied Response for any Set-Cookie headers.
     * Creates a new Cookie based on the Request URL embedded in the Response, and the
     * value of the Set-Cookie header, and appends it to the end of the list of cookies
     * for that particular domain and path, and with that particular name.
     * @param response The Response to parse for Set-Cookie headers. The Response must contain the
     * embedded Request that generated the Response.
     */
    public void updateCookies(Response response) {
        String[][] headers = response.getHeaders();
        for (int i=0; i< headers.length; i++) {
            if (headers[i][0].equals("Set-Cookie")) {
                String setCookie = headers[i][1];
                Request request = response.getRequest();
                String datestr = response.getHeader("Date");
                Date date = null;
                if (datestr != null) {
                    try {
                        date = DateUtil.parseRFC822(datestr);
                    } catch (ParseException pe) {
                        date = new Date();
                    }
                } else {
                    date = new Date();
                }
                addCookie(new Cookie(date, request.getURL(), setCookie));
            }
        }
    }
    
    /** Calculates which cookies would be appropriate for the supplied Request. Updates
     * the Request with the Cookies.
     * @param request The Request to add the Cookies to.
     */
    public void addRequestCookies(Request request) {
        URL url = request.getURL();
        Cookie[] cookies = getCookiesForURL(url);
        String header = request.getHeader("Cookie");
        // if (header != null) {
        // here we should check to see if the existing cookie has been
        // superceded by another more recent one, so that we can update it?
        // it is also possible for an unknown cookie to come through, if
        // f.e. it is set using JavaScript. We need to do something about those
        // }
        if (cookies.length > 0) {
            Cookie cookie;
            String newheader = null;
            String name;
            String value;
            for (int i=0; i<cookies.length; i++) {
                name = cookies[i].getName();
                value = cookies[i].getValue();
                if (value.equals("")) continue;
                if (newheader == null) {
                    newheader = name + "=" + value;
                } else {
                    newheader = newheader + "; " + name + "=" + value;
                }
            }
            if (newheader != null && (header == null || !newheader.equals(header))) {
                request.setHeader("Cookie", newheader);
            }
        }
    }
    
    /** Calculates the appropriate sub-domain parts of the supplied domain
     * A cookie may be set with a subdomain, in which case, it should be
     * sent to all hosts within that subdomain. This routine calculates what
     * those subdomains are.
     * @param domain The domain to split up
     */
    private String[] domains(String host) {
        int index = host.lastIndexOf(".");
        try {  // if the last octet is numerical, it is an IP address, so return it immediately
            if (Integer.parseInt(host.substring(host.length()-1)) >-1) {
                return new String[] {host};
            }
        } catch (NumberFormatException nfe) {}
        String[] parts = host.split("\\.");
        if (parts.length>2) { // FIXME : This is very clumsy! this can be done better!
            for (int i=1; i<parts.length; i++) {
                parts[i] = "." + parts[i];
            }
            String[] domains = new String[parts.length-1];
            for (int i=parts.length-2; i>=0; i--) {
                parts[i] = parts[i] + parts[i+1];
                domains[i] = parts[i];
            }
            return domains;
        } else {
            return new String[] {host};
        }
    }
    
    public DefaultListModel getCookieList(String cookiename) {
        String domain = cookiename.substring(0, cookiename.indexOf("/"));
        String path = cookiename.substring(cookiename.indexOf("/"), cookiename.indexOf(" "));
        String name = cookiename.substring(cookiename.indexOf(" ")+1);
        DefaultListModel cookies = getCookieList(domain, path, name, false);
        if (cookies == null) {
            System.err.println("Selected a non-existent cookie list! " + cookiename);
        }
        return cookies;
    }

    private DefaultListModel getCookieList(String domain, String path, String name, boolean create) {
        synchronized(_cookies) {
            TreeMap paths = (TreeMap) _cookies.get(domain);
            if (paths == null) {
                if (create) {
                    paths = new TreeMap();
                    _cookies.put(domain, paths);
                } else return null;
            }
            TreeMap names = (TreeMap) paths.get(path);
            if (names == null) {
                if (create) {
                    names = new TreeMap();
                    paths.put(path, names);
                } else return null;
            }
            DefaultListModel cookies = (DefaultListModel) names.get(name);
            if (cookies == null) {
                if (create) {
                    cookies = new DefaultListModel();
                    names.put(name, cookies);
                } else return null;
            }
            return cookies;
        }
    }
    
    private Cookie[] getCookiesForURL(URL url) {
        String host = url.getHost();
        String path = url.getPath();
        ArrayList all = new ArrayList();
        String[] domains = domains(host);
        for (int i=0; i<domains.length; i++) {
            TreeMap pathmap = (TreeMap) _cookies.get(domains[i]);
            if (pathmap != null) {
                // FIXME we should return these cookies in order.
                // longest path match first, apparently
                Iterator paths = pathmap.keySet().iterator();
                while (paths.hasNext()) {
                    String cookiepath = (String) paths.next();
                    if (path.startsWith(cookiepath)) {
                        TreeMap namemap = (TreeMap) pathmap.get(cookiepath);
                        Iterator names = namemap.keySet().iterator();
                        while (names.hasNext()) {
                            String name = (String) names.next();
                            DefaultListModel cookies = (DefaultListModel) namemap.get(name);
                            if (cookies.size() > 0) {
                                all.add(cookies.get(cookies.size()-1));
                            }
                        }
                    }
                }
            }
        }
        return (Cookie[]) all.toArray(new Cookie[0]);
    }
    
    // used for saving the cookie jar to disk
    public Cookie[] getAllCookies() {
        ArrayList all = new ArrayList();
        Iterator hosts = _cookies.keySet().iterator();
        while (hosts.hasNext()) {
            String host = (String) hosts.next();
            TreeMap pathmap = (TreeMap) _cookies.get(host);
            Iterator paths = pathmap.keySet().iterator();
            while (paths.hasNext()) {
                String path = (String) paths.next();
                TreeMap namemap = (TreeMap) pathmap.get(path);
                Iterator names = namemap.keySet().iterator();
                while (names.hasNext()) {
                    String name = (String) names.next();
                    ArrayList cookies = (ArrayList) namemap.get(name);
                    Iterator cookie = cookies.iterator();
                    while (cookie.hasNext()) {
                        all.add(cookie.next());
                    }
                }
            }
        }
        return (Cookie[]) all.toArray(new Cookie[0]);
    }
    
    public void addCookies(Cookie[] cookies) {
        ArrayList cookieList = null;
        for (int i=0; i<cookies.length; i++) {
            addCookie(cookies[i]);
        }
    }
    
    private void addCookie(Cookie cookie) {
        DefaultListModel cookies = getCookieList(cookie.getDomain(), cookie.getPath(), cookie.getName(), true);
        if (cookies.size() == 0) {
            _cookieList.addElement(cookie.getKey());
        }
        cookies.addElement(cookie);
    }
    
    public DefaultListModel getCookieList() {
        return _cookieList;
    }

}
