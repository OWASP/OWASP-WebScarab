/*
 * Util.java
 *
 * Created on April 28, 2003, 8:03 AM
 */

package org.owasp.webscarab.util;

import java.net.URL;
import java.net.MalformedURLException;
import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.ParseException;

// import org.owasp.webscarab.model.*;

/**
 *
 * @author  rdawes
 */
public class Util {
    
    /** Creates a new instance of Util */
    public Util() {
    }
    
    public static String getURLSHP(URL url) {
        String shp = url.getProtocol() + "://" + url.getHost();
        if (url.getPort() != -1) {
            shp = shp + ":" + url.getPort();
        } else {
            shp = shp + ":" + url.getDefaultPort();
        }            
        return shp;
    }
    
    public static String getURLSHPP(URL url) {
        if (url.getProtocol().toLowerCase().startsWith("http")) {
            return getURLSHP(url) + getURLPath(url);
        } else {
            return url.toString();
        }
    }
    
    public static String getURLPath(URL url) {
        String path = url.getPath();
        int pos;
        while ((pos = path.indexOf(";")) > -1) {
            int slashpos = path.indexOf("/",pos);
            if (slashpos>-1) {
                path = path.substring(0,pos) + path.substring(slashpos);
            } else {
                path = path.substring(0,pos);
            }
        }
        return path;
    }
    
    public static String getURLQuery(URL url) {
        String query = url.getQuery();
        String path = url.getPath();
        String pathquery = new String();
        int pos = -1;
        while ((pos = path.indexOf(";",pos+1)) > -1) {
            int slashpos = path.indexOf("/",pos);
            if (slashpos>-1) {
                pathquery = pathquery + path.substring(pos,slashpos);
            } else {
                pathquery = pathquery + path.substring(pos);
            }
        }
        if (!pathquery.equals("")) {
            return pathquery + "?" + (query == null ? "" : query);
        } else if (query != null && !query.equals("")) {
            return "?" + query;
        }
        return null;
    }

    public static String readLine(InputStream is) throws IOException {
        String line = new String();
        int i;
        byte[] b={(byte)0x00};
        i = is.read();
        while (i > -1 && i != 10 && i != 13) {
            // Convert the int to a byte
            // we use an array because we can't concat a single byte :-(
            b[0] = (byte)(i & 0xFF);
            String input = new String(b,0,1);
            line = line.concat(input);
            i = is.read();
        }
        if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if we got 13
            i = is.read();
        }
//        System.out.println("Read '" + line + "'");
        return line;
    }
    
    public static byte[] readContent(InputStream is, int length) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (length > 0) {
            byte[] cbuf = new byte[length];
            int chars = 0;
            while (length > 0 && chars > -1) {
                chars = is.read(cbuf,0,length);
                length = length - chars;
                baos.write(cbuf,0,chars);
            }
        } else if (length == 0) {
            return null;
        } else {
            byte[] cbuf = new byte[2048];
            int chars = is.read(cbuf,0,2048);
            while (chars > -1) {
                baos.write(cbuf,0,chars);
                chars = is.read(cbuf,0,2048);
            }
        }
        return baos.toByteArray();
    }

    // example :    Tue, 04 Mar 2003 20:26:50 GMT
    public static Date rfc822(String dateString) {
        SimpleDateFormat sdf = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z");
        Date date = null;
        try {
            date = sdf.parse(dateString);
        } catch (ParseException pe) {}
        return date;
    }

    public static String hexEncode(byte[] bytes) {
        char[] hex = new char[] { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
        StringBuffer hexBuff = new StringBuffer();
        for ( int i = 0; i < bytes.length; i++ ) {
            hexBuff.append(new char[] {hex[(bytes[i]>>4)&0xf],hex[bytes[i]&0xf]});
        }
        return hexBuff.toString().toUpperCase();
    }

    public static void main(String[] args) {
        URL url = null;
        try {
            url = new URL("http://localhost:8080/admin/path;jsessionid=abcdef/component;jsessionid=abcdef?param=1&param2=2");
        } catch (MalformedURLException mue) {
            System.out.println("MUE " + mue);
            System.exit(1);
        }
        System.out.println(Util.getURLPath(url));
        System.out.println(Util.getURLQuery(url));
    }
}
