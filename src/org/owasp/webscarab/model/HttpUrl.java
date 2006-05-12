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
 * Created on Jul 13, 2004
 *
 */
package org.owasp.webscarab.model;

import java.util.ArrayList;
import java.net.MalformedURLException;

/**
 * Represents a http or https url
 * @author knoppix
 */
public class HttpUrl implements Comparable {
    
    private static final HttpUrl[] nullPath = new HttpUrl[0];
    
    private String _scheme;
    private String _host;
    private int _port;
    private String _path;
    private String _fragment = null;
    private String _query = null;
    
    private int _hashcode;
    
    /**
     * creates an HttpUrl by parsing the supplied string
     * @param url a String representation of the URL
     * @throws MalformedURLException if the url is not well-formed
     */    
    public HttpUrl(String url) throws MalformedURLException {
        if (url.indexOf('\n') > -1 || url.indexOf(' ') > -1)
            throw new MalformedURLException("Illegal characters in url: " + url);
        parseUrl(url);
        _hashcode = this.toString().hashCode();
    }
    
    /**
     * Creates a new url, basing the supplied relative path against the supplied HttpUrl
     * @param url the existing base url
     * @param relative the relative path
     * @throws MalformedURLException if the url is malformed
     */    
    public HttpUrl(HttpUrl url, String relative) throws MalformedURLException {
        if (relative.indexOf('\n') > -1 || relative.indexOf(' ') > -1)
            throw new MalformedURLException("Illegal characters in relative : " + relative);
        // relative could be a fully qualified URL
        if (url == null || relative.startsWith("http://") || relative.startsWith("https://")) { 
            parseUrl(relative);
            _hashcode = this.toString().hashCode();
            return;
        }
        _scheme = url.getScheme();
        _host = url.getHost();
        _port = url.getPort();
        if (relative.startsWith("/")) { // an absolute path
            _path = relative;
        } else {
            _path = relativePath(url.getPath(), relative);
        }
        splitFragQuery();
        _path = _path.replaceAll(" ", "%20");
        if (_query != null) _query = _query.replace(' ', '+');
        if (_fragment != null) _fragment = _fragment.replaceAll(" ", "%20");
        _hashcode = this.toString().hashCode();
    }
    
    private void parseUrl(String url) throws MalformedURLException {
        int pos = url.indexOf("://");
        if (pos == -1)
            throw new MalformedURLException("An URL must have a scheme!");
        _scheme = url.substring(0, pos).toLowerCase();
        if (!_scheme.equals("http") && !_scheme.equals("https"))
            throw new MalformedURLException("This class only supports HTTP or HTTPS schemes: '"+_scheme+"'");
        int prev = pos + 3;
        pos = url.indexOf("/", prev);
        if (pos == -1)
            pos = url.length();
        String hp = url.substring(prev, pos);
        int colon = hp.indexOf(":");
        if (colon == -1) {
            _host = hp;
            if (_scheme.equals("http")) {
                _port = 80;
            } else if (_scheme.equals("https")) {
                _port = 443;
            }
        } else {
            try {
                _host = hp.substring(0, colon);
                _port = Integer.parseInt(hp.substring(colon + 1));
            } catch (NumberFormatException nfe) {
                throw new MalformedURLException("Error parsing the port number: " + nfe);
            }
        }
        if ("".equals(_host))
            throw new MalformedURLException("Host cannot be empty");
        if (_port < 1 || _port > 65535)
            throw new MalformedURLException("Port out of range: " + _port);
        if (pos == url.length()) {
            _path = "/";
        } else {
            _path = url.substring(pos);
            splitFragQuery();
        }
    }
    
    private String relativePath(String oldPath, String relative) {
        if (!oldPath.endsWith("/")) { // trim the file part
            oldPath = parentPath(oldPath);
        }
        
        while (relative.startsWith("../") || relative.startsWith("./")) {
            if (relative.startsWith("./")) { // trim meaningless self-ref
                relative = relative.substring(2);
            } else {
                relative = relative.substring(3);
                if (oldPath.length()>1) {
                    oldPath = parentPath(oldPath);
                }
            }
        }
        return oldPath + relative;
    }
    
    private void splitFragQuery() {
        // Anchors are meaningless to us in this context
        int hash = _path.indexOf("#");
        if (hash > -1) _path = _path.substring(0, hash);
        
        int ques = _path.indexOf("?");
        if (ques > -1) {
            _query = _path.substring(ques + 1);
            _path = _path.substring(0, ques);
        }
        int semi = _path.indexOf(";");
        if (semi > -1) {
            _fragment = _path.substring(semi + 1);
            _path = _path.substring(0, semi);
        }
    }
    
    /**
     * returns the schem of the url
     * @return Returns the scheme.
     */
    public String getScheme() {
        return _scheme;
    }
    
    /**
     * returns the host part of the url
     * @return Returns the host.
     */
    public String getHost() {
        return _host;
    }
    
    /**
     * returns the port
     * @return Returns the port.
     */
    public int getPort() {
        return _port;
    }
    
    /**
     * returns the "file path" of the URL, excluding any fragments or queries
     * @return Returns the path.
     */
    public String getPath() {
        return _path;
    }
    
    /**
     * returns the fragment part of the url, or null if none exists
     * @return Returns the fragment.
     */
    public String getFragment() {
        return _fragment;
    }
    
    /**
     * returns the query part of the url, or null if none exists
     * @return Returns the query.
     */
    public String getQuery() {
        return _query;
    }
    
    /**
     * returns a string representation of the url, excluding any fragments
     * or query parts
     * @return the string representation of the URL, excluding any fragments or query
     */
    public String getSHPP() {
        StringBuffer buff = new StringBuffer();
        buff.append(_scheme).append("://");
        buff.append(_host).append(":").append(_port);
        buff.append(_path);
        return buff.toString();
    }
    
    /**
     * returns a string representation of the parameters passed to the url
     * @return the string representation of the parameters
     */
    public String getParameters() {
        if (_fragment == null && _query == null) return null;
        StringBuffer buff = new StringBuffer();
        if (_fragment != null) buff.append(";").append(_fragment);
        if (_query != null) buff.append("?").append(_query);
        return buff.toString();
    }
    
    private String parentPath(String path) {
        int secondlast = path.lastIndexOf("/",path.length()-2);
        return path.substring(0,secondlast+1);
    }
    
    /**
     * returns the parent of this Url.
     * @return the parent of this Url, or null if this is a top-level Url
     */    
    public HttpUrl getParentUrl() {
        if (_scheme.equals("")) throw new NullPointerException("Should not be trying to get the parent of NULL URL");
        try {
            if (_fragment != null || _query != null) {
                return new HttpUrl(getSHPP());
            } else if (_path != null && _path.length() > 1) {
                String url = getSHPP();
                int secondLast = url.lastIndexOf("/",url.length()-2);
                return new HttpUrl(url.substring(0, secondLast+1));
            } else {
                return null;
            }
        } catch (MalformedURLException mue) {
            System.err.println("Malformed URL calculating parent path of " + toString());
            return null;
        }
    }
    
    /**
     * returns an array containing the Url hierarchy, including this Url
     * @return an array of the Url hierarchy
     */    
    public HttpUrl[] getUrlHierarchy() {
        ArrayList list = new ArrayList();
        list.add(this);
        HttpUrl url = getParentUrl();
        while (url != null) {
            list.add(0, url);
            url = url.getParentUrl();
        }
        return (HttpUrl[]) list.toArray(nullPath);
    }
    
    /**
     * returns a string representation of the URL, in fully qualified form
     * @return the fully qualifed url
     */    
    public String toString() {
        if (_scheme.equals("")) return "NULL URL";
        StringBuffer buff = new StringBuffer();
        buff.append(_scheme).append("://");
        buff.append(_host).append(":").append(_port);
        return direct(buff).toString();
    }
    
    /**
     * appends the /path;fragment?query part of the URL to the supplied buffer
     * @param buff a StrinBuffer to append the URL to
     * @return the buffer
     */    
    public StringBuffer direct(StringBuffer buff) {
        buff.append(_path);
        if (_fragment != null) buff.append(";").append(_fragment);
        if (_query != null) buff.append("?").append(_query);
        return buff;
    }
    
    /**
     * returns only the /path;fragment?query part of the URL
     * @return the /path;fragment?query part of the URL
     */    
    public String direct() {
        return direct(new StringBuffer()).toString();
    }
    
    /**
     * Indicates whether some other object is "equal to" this one.
     * <p>
     * The <code>equals</code> method implements an equivalence relation
     * on non-null object references:
     * <ul>
     * <li>It is <i>reflexive</i>: for any non-null reference value
     *     <code>x</code>, <code>x.equals(x)</code> should return
     *     <code>true</code>.
     * <li>It is <i>symmetric</i>: for any non-null reference values
     *     <code>x</code> and <code>y</code>, <code>x.equals(y)</code>
     *     should return <code>true</code> if and only if
     *     <code>y.equals(x)</code> returns <code>true</code>.
     * <li>It is <i>transitive</i>: for any non-null reference values
     *     <code>x</code>, <code>y</code>, and <code>z</code>, if
     *     <code>x.equals(y)</code> returns <code>true</code> and
     *     <code>y.equals(z)</code> returns <code>true</code>, then
     *     <code>x.equals(z)</code> should return <code>true</code>.
     * <li>It is <i>consistent</i>: for any non-null reference values
     *     <code>x</code> and <code>y</code>, multiple invocations of
     *     <tt>x.equals(y)</tt> consistently return <code>true</code>
     *     or consistently return <code>false</code>, provided no
     *     information used in <code>equals</code> comparisons on the
     *     objects is modified.
     * <li>For any non-null reference value <code>x</code>,
     *     <code>x.equals(null)</code> should return <code>false</code>.
     * </ul>
     * <p>
     * The <tt>equals</tt> method for class <code>Object</code> implements
     * the most discriminating possible equivalence relation on objects;
     * that is, for any non-null reference values <code>x</code> and
     * <code>y</code>, this method returns <code>true</code> if and only
     * if <code>x</code> and <code>y</code> refer to the same object
     * (<code>x == y</code> has the value <code>true</code>).
     * <p>
     * Note that it is generally necessary to override the <tt>hashCode</tt>
     * method whenever this method is overridden, so as to maintain the
     * general contract for the <tt>hashCode</tt> method, which states
     * that equal objects must have equal hash codes.
     *
     * @param   o   the reference object with which to compare.
     * @return  <code>true</code> if this object is the same as the obj
     *          argument; <code>false</code> otherwise.
     * @see     #hashCode()
     * @see     java.util.Hashtable
     */
    public boolean equals(Object o) {
        if (! (o instanceof HttpUrl)) return false;
        if (_hashcode != o.hashCode()) return false;
        return compareTo(o) == 0;
    }
    
    /**
     * Compares this object with the specified object for order.  Returns a
     * negative integer, zero, or a positive integer as this object is less
     * than, equal to, or greater than the specified object.<p>
     *
     * In the foregoing description, the notation
     * <tt>sgn(</tt><i>expression</i><tt>)</tt> designates the mathematical
     * <i>signum</i> function, which is defined to return one of <tt>-1</tt>,
     * <tt>0</tt>, or <tt>1</tt> according to whether the value of <i>expression</i>
     * is negative, zero or positive.
     *
     * The implementor must ensure <tt>sgn(x.compareTo(y)) ==
     * -sgn(y.compareTo(x))</tt> for all <tt>x</tt> and <tt>y</tt>.  (This
     * implies that <tt>x.compareTo(y)</tt> must throw an exception iff
     * <tt>y.compareTo(x)</tt> throws an exception.)<p>
     *
     * The implementor must also ensure that the relation is transitive:
     * <tt>(x.compareTo(y)&gt;0 &amp;&amp; y.compareTo(z)&gt;0)</tt> implies
     * <tt>x.compareTo(z)&gt;0</tt>.<p>
     *
     * Finally, the implementer must ensure that <tt>x.compareTo(y)==0</tt>
     * implies that <tt>sgn(x.compareTo(z)) == sgn(y.compareTo(z))</tt>, for
     * all <tt>z</tt>.<p>
     *
     * It is strongly recommended, but <i>not</i> strictly required that
     * <tt>(x.compareTo(y)==0) == (x.equals(y))</tt>.  Generally speaking, any
     * class that implements the <tt>Comparable</tt> interface and violates
     * this condition should clearly indicate this fact.  The recommended
     * language is "Note: this class has a natural ordering that is
     * inconsistent with equals."
     * @param o the Object to be compared.
     * @return a negative integer, zero, or a positive integer as this object
     * 		is less than, equal to, or greater than the specified object.
     */
    public int compareTo(Object o) {
        if (o == null) return 1;
        
        if (! (o instanceof HttpUrl)) throw new ClassCastException("Can only compare HttpUrls, not a " + o.getClass().getName());
        
        HttpUrl url = (HttpUrl) o;
        int result;
        
        result = _scheme.compareTo(url.getScheme());
        if (result != 0) return result;
        
        result = _host.compareTo(url.getHost());
        if (result != 0) return result;
        
        result = _port - url.getPort();
        if (result != 0) return result;
        
        result = _path.compareTo(url.getPath());
        if (result != 0) return result;
        
        if (_fragment == null) {
            if (url.getFragment() == null) { result = 0; }
            else { result = -1; }
        } else {
            if (url.getFragment() == null) { result = 1; }
            else { result = _fragment.compareTo(url.getFragment()); }
        }
        if (result != 0) return result;
        
        if (_query == null) {
            if (url.getQuery() == null) { result = 0; }
            else { result = -1; }
        } else {
            if (url.getQuery() == null) { result = 1; }
            else { result = _query.compareTo(url.getQuery()); }
        }
        return result;
    }
    
    /**
     * Returns a hash code value for the object. This method is
     * supported for the benefit of hashtables such as those provided by
     * <code>java.util.Hashtable</code>.
     * <p>
     * The general contract of <code>hashCode</code> is:
     * <ul>
     * <li>Whenever it is invoked on the same object more than once during
     *     an execution of a Java application, the <tt>hashCode</tt> method
     *     must consistently return the same integer, provided no information
     *     used in <tt>equals</tt> comparisons on the object is modified.
     *     This integer need not remain consistent from one execution of an
     *     application to another execution of the same application.
     * <li>If two objects are equal according to the <tt>equals(Object)</tt>
     *     method, then calling the <code>hashCode</code> method on each of
     *     the two objects must produce the same integer result.
     * <li>It is <em>not</em> required that if two objects are unequal
     *     according to the {@link java.lang.Object#equals(java.lang.Object)}
     *     method, then calling the <tt>hashCode</tt> method on each of the
     *     two objects must produce distinct integer results.  However, the
     *     programmer should be aware that producing distinct integer results
     *     for unequal objects may improve the performance of hashtables.
     * </ul>
     * <p>
     * As much as is reasonably practical, the hashCode method defined by
     * class <tt>HttpUrl</tt> does return distinct integers for distinct
     * objects. (This is implemented by converting the url to a String, and
     * returning the String's hashCode() )
     *
     * @return  a hash code value for this object.
     * @see     java.lang.Object#equals(java.lang.Object)
     * @see     java.util.Hashtable
     */
    public int hashCode() {
        return _hashcode;
    }
}
