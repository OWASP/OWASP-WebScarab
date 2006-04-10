/*
 * WebScarab.java
 *
 * Created on 06 February 2006, 04:59
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package org.owasp.webscarab;

/**
 *
 * @author rdawes
 */
public class WebScarab {
    
    /** Creates a new instance of WebScarab */
    private WebScarab() {
    }
    
    /* This class exists purely to ensure that the
     * program version information is properly loaded at run-time
     *
     * It may eventually become a dispatcher for different versions
     * of user interfaces
     */
    public static void main(String[] args) {
        if (args != null && args.length > 0) {
            if (args[0].equalsIgnoreCase("lite")) {
                if (args.length>1) {
                    String[] trim = new String[args.length-1];
                    System.arraycopy(args, 1, trim, 0, args.length-1);
                    args = trim;
                } else {
                    args = null;
                }
                org.owasp.webscarab.ui.swing.Lite.main(args);
            } else {
                org.owasp.webscarab.ui.swing.Main.main(args);
            }
        } else {
            org.owasp.webscarab.ui.swing.Main.main(args);
        }
    }
    
}
