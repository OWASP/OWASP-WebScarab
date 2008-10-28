/**
 * 
 */
package org.owasp.webscarab.util;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.logging.Logger;

import org.owasp.webscarab.model.HttpUrl;
import org.owasp.webscarab.model.NamedValue;
import org.owasp.webscarab.model.Request;

/**
 * @author rdawes
 *
 */
public class RequestConverter {

    private static Logger _logger = Logger.getLogger("org.owasp.webscarab.util.RequestConverter");
    
    public static Request convertGetToPost(Request get) {
        if (!"GET".equals(get.getMethod()))
            throw new IllegalArgumentException("Request must be a GET, not a " + get.getMethod());
        Request post = new Request();
        post.setMethod("POST");
        HttpUrl url = get.getURL();
        String query = url.getQuery();
        if (query != null) {
            try {
                post.setContent(query.getBytes("ASCII"));
            } catch (UnsupportedEncodingException uee) {
                _logger.severe("Bizarre! " + uee.getLocalizedMessage());
                RuntimeException e = new IllegalArgumentException("Unknown ASCII encoding!");
                e.initCause(uee);
                throw e;
            }
            String s = url.toString();
            int q = s.indexOf('?');
            s = s.substring(0, q);
            try {
                post.setURL(new HttpUrl(s));
            } catch (MalformedURLException mue) {
                throw new RuntimeException("Couldn't extract the POST url!", mue);
            }
        } else {
            post.setURL(url);
        }
        post.setVersion(get.getVersion());
        post.setHeaders(get.getHeaders());
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        post.setHeader("Content-Length", Integer.toString(query == null ? 0 : query.length()));
        return post;
    }
    
    public static Request convertPostToMultipart(Request post) {
        if (!"application/x-www-form-urlencoded".equals(post.getHeader("Content-Type")))
            throw new IllegalArgumentException("Content type incorrect, was " + post.getHeader("Content-Type"));
        StringBuffer buff = new StringBuffer();
        Request multipart = new Request(post);
        byte[] content = post.getContent();
        if (content == null) 
            content = new byte[0];
        String sep = Encoding.hashMD5(content);
        String contentType = "multipart/form-data; boundary=" + sep;
        String boundary = "--" + sep;
        String disposition = "Content-Disposition: form-data; name=";
        NamedValue[] nvs = NamedValue.splitNamedValues(new String(content), "&", "=");
        buff.append(boundary);
        for (int i=0; i<nvs.length; i++) {
            buff.append("\r\n").append(disposition).append("\"").append(nvs[i].getName()).append("\"\r\n\r\n");
            buff.append(nvs[i].getValue()).append("\r\n").append(boundary);
        }
        buff.append("--\r\n");
        multipart.setHeader("Content-Type", contentType);
        multipart.setHeader("Content-Length", Integer.toString(buff.length()));
        multipart.setContent(buff.toString().getBytes());
        return multipart;
    }
    
    public static Request convertGetToMultipartPost(Request request) {
        return convertPostToMultipart(convertGetToPost(request));
    }
    
    public static Request convertPostToGet(Request post) {
        if (!"application/x-www-form-urlencoded".equals(post.getHeader("Content-Type")))
            throw new IllegalArgumentException("Content type incorrect, was " + post.getHeader("Content-Type"));
        byte[] content = post.getContent();
        Request get = new Request(post);
        get.setMethod("GET");
        get.setContent(null);
        get.deleteHeader("Content-Type");
        get.deleteHeader("Content-Length");
        String query = "";
        if (content != null) {
            query = new String(content);
            try {
                HttpUrl url = get.getURL();
                if (url.getQuery() != null) {
                    url = new HttpUrl(url.toString() + "&" + query);
                } else if (url.getQuery() == null) {
                    url = new HttpUrl(url.toString() + "?" + query);
                }
                get.setURL(url);
            } catch (MalformedURLException mue) {
                throw new RuntimeException("Couldn't construct the URL", mue);
            }
        }
        return get;
    }
    
    public static void main(String[] args) throws Exception {
        Request get = new Request();
        get.setMethod("GET");
        get.setURL(new HttpUrl("http://localhost/WebGoat/attack;fragment?a=1&b=nanana"));
        get.setVersion("HTTP/1.0");
        get.setHeader("Host", "localhost");
        System.out.println(get +"\r\n=============\r\n");
        Request post = convertGetToPost(get);
        System.out.println(post + "\r\n==============\r\n");
        Request multipart = convertPostToMultipart(post);
        System.out.println(multipart + "\r\n================\r\n");
        convertPostToMultipart(multipart);
    }
}
