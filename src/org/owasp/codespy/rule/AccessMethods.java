package org.owasp.codespy.rule;

import java.beans.Introspector;
import java.beans.BeanInfo;
import java.beans.PropertyDescriptor;
import java.beans.IntrospectionException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import org.owasp.codespy.Reference;
import org.owasp.codespy.Result;
import org.owasp.codespy.AtomicRule;
import org.owasp.codespy.Severity;
import org.owasp.codespy.ClassProxy;

/** 
 * Rule that states that classes should not declare
 * non-private, non-final methods to access instance fields. The access
 * methods must follow the JavaBean naming convention to be discovered.
 * @author Mark Curphey
 * @version 1.0
 */
public class AccessMethods 
	extends AtomicRule 
{
	/** *  Reference for the rule. */
	private static final String MSG = "Access methods to fields must be final or private.";
	private static final Reference ref = new Reference( MSG );
	// for testing purposes only.
	private int foo; // should fire on self-reference test
	private int bar; // should not fire on self-reference test
	private int bas; // should not fire on self-reference test
	
	/** 
	 * Constructs a instance of the rule with the provided severity.
	 * @param severity the severity to assign an infraction.
	 */
	public AccessMethods ( Severity severity ) {
		super( ref, severity );
	}

	/** 
	 * Registers a result if this class declares non-private, non-final
	 * methods to access instance fields. The access method must follow the
	 * JavaBean naming convention to be discovered.
	 * @param target the class to evaluate.
	 */
	protected final void test ( ClassProxy target ) {
		String msg = getSeverity()
		              + ": this class declares non-private, non-final access method ";
		Field[] fields = target.getDeclaredFields();
		for ( int i = 0; i < fields.length; i++ ) {
			// check for reader
			Method method = findGetMethod( target.getProxiedClass(), fields[ i ] );
			if ( method != null && !Modifier.isFinal( method.getModifiers() )
			      && !Modifier.isPrivate( method.getModifiers() ) )
				addResult( new Result( this, msg + method, getSeverity() ) );
			// check for writer
			method = findSetMethod( target.getProxiedClass(), fields[ i ] );
			if ( method != null && !Modifier.isFinal( method.getModifiers() )
			      && !Modifier.isPrivate( method.getModifiers() ) )
				addResult( new Result( this, msg + method, getSeverity() ) );
		}
	}

	/** 
	 * Returns the read method of a JavaBean property.
	 * @param target the JavaBean class.
	 * @param field the JavaBean property.
	 * @return the read method of a JavaBean property.
	 */
	private final Method findGetMethod ( Class target, Field field ) {
		/** *  Get JavaBean properties. */
		PropertyDescriptor[] pd = null;
		try {
			pd = Introspector.getBeanInfo( target ).getPropertyDescriptors();
		} 
		catch ( IntrospectionException e ) {
			return null; // exit if no properties
			}
		/** *  Search for reader. */
		for ( int i = 0; i < pd.length; i++ ) 
			if ( pd[ i ].getName().equals( field.getName() ) )
				// test the parameter type
				if ( pd[ i ].getPropertyType().equals( field.getType() ) )
					return pd[ i ].getReadMethod();
		return null;
	}

	/** 
	 * Returns the write method of a JavaBean property.
	 * @param target the JavaBean class.
	 * @param field the JavaBean property.
	 * @returns the write method of a JavaBean property.
	 */
	private final Method findSetMethod ( Class target, Field field ) {
		/** *  Get JavaBean properties. */
		PropertyDescriptor[] pd = null;
		try {
			pd = Introspector.getBeanInfo( target ).getPropertyDescriptors();
		} 
		catch ( IntrospectionException e ) {
			return null; // bail if no properties
			}
		/** *  Search for write property. */
		for ( int i = 0; i < pd.length; i++ ) 
			if ( pd[ i ].getName().equals( field.getName() ) )
				// test the parameter type
				if ( pd[ i ].getPropertyType().equals( field.getType() ) )
					return pd[ i ].getWriteMethod();
		return null;
	}

	/** *  Self-reference test method. */
	public void setFoo ( int foo ) {}

	/** *  Self-reference test method. */
	public int getFoo () {
		return 0;
	}

	/** *  Self-reference test method. */
	public final void setBar ( int bar ) {}

	/** *  Self-reference test method. */
	public final int getBar () {
		return 0;
	}

	/** *  Self-reference test method. */
	private void setBas ( int bas ) {}

	/** *  Self-reference test method. */
	private int getBas () {
		return 0;
	}
}

