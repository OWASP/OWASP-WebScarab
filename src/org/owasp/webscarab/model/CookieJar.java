/*
 * CookieJar.java
 *
 * Created on September 10, 2003, 11:44 PM
 */

package org.owasp.webscarab.model;

import java.util.TreeMap;
import java.util.ArrayList;
import java.util.Iterator;

import java.net.URL;
import java.net.MalformedURLException;

import org.owasp.webscarab.httpclient.URLFetcher;

/** This class serves as a repository and parser of Cookies seen in Responses.
 * It also provides methods for populating a Request with the appropriate Cookies
 * for the Request domain and path.
 * @author rdawes
 */
public class CookieJar {
    
    private TreeMap _cookies = new TreeMap();
    
    /** Creates a new instance of CookieJar */
    public CookieJar() {
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
                Cookie cookie = new Cookie(request.getURL(), setCookie);
                ArrayList cookies = getCookieList(cookie.getDomain(), cookie.getPath(), cookie.getName());
                cookies.add(cookie);
            }
        }
    }
    
    /** Calculates which cookies would be appropriate for the supplied Request. Updates
     * the Request with the Cookies.
     * @param request The Request to add the Cookies to.
     */    
    public void addRequestCookies(Request request) {
        String host = request.getURL().getHost();
        String path = request.getURL().getPath();
        ArrayList cookies = getAllCookies(host, path);
        String header = request.getHeader("Cookie");
        // if (header != null) {
            // here we should check to see if the existing cookie has been 
            // superceded by another more recent one, so that we can update it?
            // it is also possible for an unknown cookie to come through, if
            // f.e. it is set using JavaScript. We need to do something about those
        // }
        if (cookies.size() > 0) {
            Cookie cookie;
            String newheader = null;
            String name;
            String value;
            for (int i=0; i<cookies.size(); i++) {
                cookie = (Cookie) cookies.get(i);
                name = cookie.getName();
                value = cookie.getValue();
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
        try {
            if (Integer.parseInt(host.substring(host.length()-1)) >-1) {
                return new String[] {host};
            }
        } catch (NumberFormatException nfe) {}
        String[] parts = host.split("\\.");
        if (parts.length>2) {
            String[] domains = new String[parts.length-1];
            for (int i=parts.length-2; i>=0; i--) {
                parts[i] = parts[i] + "." + parts[i+1];
                domains[i] = parts[i];
            }
            return domains;
        } else {
            return new String[] {host};
        }
    }
    
    private ArrayList getCookieList(String domain, String path, String name) {
        synchronized(_cookies) {
            TreeMap paths = (TreeMap) _cookies.get(domain);
            if (paths == null) {
                paths = new TreeMap();
                _cookies.put(domain, paths);
            }
            TreeMap names = (TreeMap) paths.get(path);
            if (names == null) {
                names = new TreeMap();
                paths.put(path, names);
            }
            ArrayList cookies = (ArrayList) names.get(name);
            if (cookies == null) {
                cookies = new ArrayList();
                names.put(name, cookies);
            }
            return cookies;
        }
    }
    
    private ArrayList getAllCookies(String host, String path) {
        // FIXME we should return these cookies in order.
        // most specific host first, then longest path match first
        ArrayList all = new ArrayList();
        String[] domains = domains(host);
        for (int i=0; i<domains.length; i++) {
            TreeMap pathmap = (TreeMap) _cookies.get(domains[i]);
            if (pathmap != null) {
                Iterator paths = pathmap.keySet().iterator();
                while (paths.hasNext()) {
                    String cookiepath = (String) paths.next();
                    if (path.startsWith(cookiepath)) {
                        TreeMap namemap = (TreeMap) pathmap.get(cookiepath);
                        Iterator names = namemap.keySet().iterator();
                        while (names.hasNext()) {
                            String name = (String) names.next();
                            ArrayList cookies = (ArrayList) namemap.get(name);
                            if (cookies.size() > 0) {
                                all.add(cookies.get(cookies.size()-1));
                            }
                        }
                    }
                }
            }
        }
        return all;
    }
    
}
