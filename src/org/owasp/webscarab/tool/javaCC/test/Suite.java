package org.owasp.webscarab.tool.javaCC.test;

import junit.framework.*;

/**
 * <TODO description>
 *
 * @since release <RELEASE>
 * @version release <RELEASE><br />$Revision: 1.1 $ $Author: istr $
 * @author <AUTHOR>
 */
public class Suite {
  

  public static Test suite () {
    TestSuite suite = new TestSuite( "org.owasp.webscarab.tool.javaCC tests" );
    suite.addTest( FormatTest.suite() );
    return suite;
  }
}

