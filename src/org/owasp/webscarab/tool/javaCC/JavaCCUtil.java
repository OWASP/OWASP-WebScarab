package org.owasp.webscarab.tool.javaCC;


/**
 * <TODO description>
 *
 * @since release <RELEASE>
 * @version release <RELEASE><br />$Revision: 1.1 $ $Author: istr $
 * @author <AUTHOR>
 */
public final class JavaCCUtil {
  
  private JavaCCUtil () {}

  public static boolean isConst ( Node node ) {
    Node child = node;
    return (0 < child.jjtGetNumChildren())
            && null != (child = child.jjtGetChild( 0 ))
            && (0 < child.jjtGetNumChildren())
            && null != (child = child.jjtGetChild( 0 ))
            && (0 < child.jjtGetNumChildren())
            && null != (child = child.jjtGetChild( 0 ))
            && (0 < child.jjtGetNumChildren())
            && null != (child = child.jjtGetChild( 0 ))
            && (1 == child.jjtGetNumChildren())
            && null != (child = child.jjtGetChild( 0 ))
            && (child instanceof NodeToken
               || child instanceof NodeKeyword);
  }
}

