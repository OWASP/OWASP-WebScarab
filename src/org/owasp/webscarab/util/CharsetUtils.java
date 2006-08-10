/**
 *
 */
package org.owasp.webscarab.util;

import org.mozilla.intl.chardet.nsDetector;
import org.mozilla.intl.chardet.nsICharsetDetectionObserver;
import org.mozilla.intl.chardet.nsPSMDetector;

/**
 * @author rdawes
 *
 */
public class CharsetUtils {
    
    public static String getCharset(byte[] bytes) {
        nsDetector det = new nsDetector(nsPSMDetector.ALL);
        CharsetListener listener = new CharsetListener();
        det.Init(listener);
        
        boolean isAscii = det.isAscii(bytes,bytes.length);
        // DoIt if non-ascii and not done yet.
        if (!isAscii)
            det.DoIt(bytes,bytes.length, false);
        det.DataEnd();
        if (isAscii) return "ASCII";
        
        return listener.getCharset();
    }
    
    private static class CharsetListener implements nsICharsetDetectionObserver {
        
        private String charset = null;
        
        public void Notify(String charset) {
            this.charset = charset;
        }
        
        public String getCharset() {
            return this.charset;
        }
        
    }
    
}
