package org.owasp.webscarab.tool.javaCC;

import java.util.ArrayList;
import java.util.Iterator;
import java.io.PrintStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.ByteArrayOutputStream;

/**
 * Generates statistics of a java source file.
 *
 * @since beta 1
 * @version beta 1<br />$Revision: 1.1 $ $Author: istr $
 * @author istr
 */
public class Statistics 
  implements JavaOneDotTwoVisitor, JavaOneDotTwoConstants 
{
  int _publicMethods;
  ArrayList _nestedClasses;
  ArrayList _nestedInterfaces;
  PrintStream _out;
  
  /**
   * Creates a new Statistics instance. 
   */
  public Statistics ( PrintStream out ) {
    _out = out;
    _publicMethods = 0;
    _nestedClasses = new ArrayList();
    _nestedInterfaces = new ArrayList();
  }

  public void print ( SimpleNode n ) {
    n.jjtAccept( this, null );
    _out.println( "public methods: " + _publicMethods );
    _out.println( "nested classes: " + _nestedClasses.size() );
    _out.println( "nested interfaces: " + _nestedClasses.size() );
    _out.println();
  }

  private void recurse ( SimpleNode node, Object data, int start, int end ) {
    int cnt = node.jjtGetNumChildren();
    if ( 0 < cnt ) {
      for ( int i = start; i < end; i++ ) {
        SimpleNode c = (SimpleNode) node.jjtGetChild( i );
        if ( null != c )
          c.jjtAccept( this, data );
        
      }
    }
  }

  private boolean isPublic ( Node node ) {
    for ( int i = 0; i < node.jjtGetNumChildren(); i++ ) {
      Node n = node.jjtGetChild( 0 );
      if ( n instanceof NodeKeyword
            && "public".equals( ((SimpleNode) n).getToken().image ) )
        return true;
      
    }
    return false;
  }

  private void recurse ( SimpleNode node, Object data ) {
    recurse( node, data, 0, node.jjtGetNumChildren() );
  }

  public Object visit ( SimpleNode node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeCompilationUnit node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeModifiers node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePackageDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeImportDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeTypeDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeClassDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeUnmodifiedClassDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeClassBody node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeNestedClassDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeClassBodyDeclaration node, Object data ) {
    Node n = node.jjtGetChild( 0 );
    if ( n instanceof NodeNestedClassDeclaration ) {
      ByteArrayOutputStream bao = new ByteArrayOutputStream();
      Statistics stat = new Statistics( new PrintStream( bao ) );
      stat.print( (SimpleNode) n );
      _nestedClasses.add( bao.toString() );
      return data;
    }
    if ( n instanceof NodeNestedInterfaceDeclaration ) {
      ByteArrayOutputStream bao = new ByteArrayOutputStream();
      Statistics stat = new Statistics( new PrintStream( bao ) );
      stat.print( (SimpleNode) n );
      _nestedInterfaces.add( bao.toString() );
      return data;
    }
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeMethodDeclarationLookahead node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeInterfaceDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeNestedInterfaceDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeUnmodifiedInterfaceDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeInterfaceMemberDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeFieldDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeVariableDeclaratorList node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeVariableDeclarator node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeVariableDeclaratorId node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeVariableInitializer node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeArrayInitializer node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeMethodDeclaration node, Object data ) {
    if ( isPublic( node.jjtGetChild( 0 ) ) )
      _publicMethods++;
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeMethodDeclarator node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeFormalParameters node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeFormalParameter node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeConstructorDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeUnmodifiedConstructorDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeConstructorBody node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeExplicitConstructorInvocation node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeInitializer node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeType node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePrimitiveType node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeResultType node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeName node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeNameList node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeAssignmentOperator node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeConditionalExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeConditionalOrExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeConditionalAndExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeInclusiveOrExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeExclusiveOrExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeAndExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeEqualityExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeInstanceOfExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeRelationalExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeShiftExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeAdditiveExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeMultiplicativeExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeUnaryExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePreIncrementExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePreDecrementExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeUnaryExpressionNotPlusMinus node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeCastLookahead node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePostfixExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeCastExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePrimaryExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePrimaryPrefix node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodePrimarySuffix node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeLiteral node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeBooleanLiteral node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeNullLiteral node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeArguments node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeArgumentList node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeAllocationExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeArrayDimsAndInits node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeLabeledStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeBlock node, Object data ) {
    return data;
  }

  public Object visit ( NodeBlockStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeLocalVariableDeclaration node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeEmptyStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeStatementExpression node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeSwitchStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeSwitchLabel node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeIfStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeWhileStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeDoStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeForStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeForControl node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeForInit node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeStatementExpressionList node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeForUpdate node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeBreakStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeContinueStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeReturnStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeThrowStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeSynchronizedStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeTryStatement node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeCatchBlock node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeFinallyBlock node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeToken node, Object data ) {
    recurse( node, data );
    return data;
  }

  public Object visit ( NodeKeyword node, Object data ) {
    recurse( node, data );
    return data;
  }
  
} // Format

