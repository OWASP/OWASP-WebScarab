package org.owasp.codespy;

import java.lang.reflect.Field;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.io.InputStream;
import java.net.URL;
import java.security.ProtectionDomain;
import java.util.Vector;

/** 
 * Proxy access to {@link java.lang.Class} that provides additional
 * information otherwise unavailable. Any information not available from
 * {@link java.lang.Class} should be implemented by this class. Currently,
 * the class provides a list of known direct subclasses for a given class.
 * @author Mark Curphey
 * @version 1.0
 */
public final class ClassProxy {
	/** *  The class to proxy. */
	private Class target;
	/** *  Direct subclasses. */
	private Class[] subclasses;
	
	/** 
	 * Construct a class proxy instance. Additional information gathered
	 * about a class currently consists of direct known subclasses. A direct
	 * known subclass is any class made known through the known parameter
	 * that that explicitly extends the proxied class.
	 * @param target the class to proxy.
	 * @param known the list of known classes to be used in determining additional
	 * information about the class.
	 */
	public ClassProxy ( Class target, Class[] known ) {
		this.target = target;
		// determine any direct subclasses in specified list
		Vector v = new Vector();
		for ( int i = 0; i < known.length; i++ ) 
			if ( target.equals( known[ i ].getSuperclass() ) )
				v.addElement( known[ i ] );
		subclasses = new Class[v.size()];
		v.copyInto( subclasses );
	}

	/** *  Proxy to {@link java.lang.Class#forName(String)}. */
	public static Class forName ( String name )
		throws ClassNotFoundException
	{
		return Class.forName( name );
	}

	/** *  Proxy to {@link java.lang.Class#forName(String,boolean,ClassLoader)}. */
	public static Class forName ( String name, boolean init, ClassLoader load )
		throws ClassNotFoundException
	{
		return Class.forName( name, init, load );
	}

	/** *  Proxy to {@link java.lang.Class#newInstance(String)}. */
	public Object newInstance ()
		throws InstantiationException, IllegalAccessException
	{
		return target.newInstance();
	}

	/** *  Proxy to {@link java.lang.Class#isInstance(Object)}. */
	public boolean isInstance ( Object obj ) {
		return target.isInstance( obj );
	}

	/** *  Proxy to {@link java.lang.Class#isAssignableFrom(Class)}. */
	public boolean isAssignableFrom ( Class c ) {
		return target.isAssignableFrom( c );
	}

	/** *  Proxy to {@link java.lang.Class#isInterface()}. */
	public boolean isInterface () {
		return target.isInterface();
	}

	/** *  Proxy to {@link java.lang.Class#isArray()}. */
	public boolean isArray () {
		return target.isArray();
	}

	/** *  Proxy to {@link java.lang.Class#isPrimitive()}. */
	public boolean isPrimitive () {
		return target.isPrimitive();
	}

	/** *  Proxy to {@link java.lang.Class#getName()}. */
	public String getName () {
		return target.getName();
	}

	/** *  Proxy to {@link java.lang.Class#getClassLoader()}. */
	public ClassLoader getClassLoader () {
		return target.getClassLoader();
	}

	/** *  Proxy to {@link java.lang.Class#getSuperclass()}. */
	public Class getSuperclass () {
		return target.getSuperclass();
	}

	/** *  Proxy to {@link java.lang.Class#getPackage()}. */
	public Package getPackage () {
		return target.getPackage();
	}

	/** *  Proxy to {@link java.lang.Class#getInterfaces()}. */
	public Class[] getInterfaces () {
		return target.getInterfaces();
	}

	/** *  Proxy to {@link java.lang.Class#getComponentType()}. */
	public Class getComponentType () {
		return target.getComponentType();
	}

	/** *  Proxy to {@link java.lang.Class#getModifiers()}. */
	public int getModifiers () {
		return target.getModifiers();
	}

	/** *  Proxy to {@link java.lang.Class#getSigners()}. */
	public Object[] getSigners () {
		return target.getSigners();
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaringClass()}. */
	public Class getDeclaringClass () {
		return target.getDeclaringClass();
	}

	/** *  Proxy to {@link java.lang.Class#getClasses()}. */
	public Class[] getClasses () {
		return target.getClasses();
	}

	/** *  Proxy to {@link java.lang.Class#getFields()}. */
	public Field[] getFields () {
		return target.getFields();
	}

	/** *  Proxy to {@link java.lang.Class#getMethods()}. */
	public Method[] getMethods () {
		return target.getMethods();
	}

	/** *  Proxy to {@link java.lang.Class#getConstructors()}. */
	public Constructor[] getConstructors () {
		return target.getConstructors();
	}

	/** *  Proxy to {@link java.lang.Class#getField(String)}. */
	public Field getField ( String name )
		throws NoSuchFieldException
	{
		return target.getField( name );
	}

	/** *  Proxy to {@link java.lang.Class#getMethod(String,Class[])}. */
	public Method getMethod ( String name, Class[] params )
		throws NoSuchMethodException
	{
		return target.getMethod( name, params );
	}

	/** *  Proxy to {@link java.lang.Class#getConstructor(Class[])}. */
	public Constructor getConstructor ( Class[] params )
		throws NoSuchMethodException
	{
		return target.getConstructor( params );
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredClasses()}. */
	public Class[] getDeclaredClasses () {
		return target.getDeclaredClasses();
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredFields()}. */
	public Field[] getDeclaredFields () {
		return target.getDeclaredFields();
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredMethods()}. */
	public Method[] getDeclaredMethods () {
		return target.getDeclaredMethods();
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredConstructors()}. */
	public Constructor[] getDeclaredConstructors () {
		return target.getDeclaredConstructors();
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredField(String)}. */
	public Field getDeclaredField ( String name )
		throws NoSuchFieldException
	{
		return target.getDeclaredField( name );
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredMethod(String,Class[])}. */
	public Method getDeclaredMethod ( String name, Class[] params )
		throws NoSuchMethodException
	{
		return target.getDeclaredMethod( name, params );
	}

	/** *  Proxy to {@link java.lang.Class#getDeclaredConstructor(Class[])}. */
	public Constructor getDeclaredConstructor ( Class[] params )
		throws NoSuchMethodException
	{
		return target.getDeclaredConstructor( params );
	}

	/** *  Proxy to {@link java.lang.Class#getResourceAsStream(String)}. */
	public InputStream getResourceAsStream ( String resource ) {
		return target.getResourceAsStream( resource );
	}

	/** *  Proxy to {@link java.lang.Class#getResource(String)}. */
	public URL getResource ( String name ) {
		return target.getResource( name );
	}

	/** *  Proxy to {@link java.lang.Class#getProtectionDomain()}. */
	public ProtectionDomain getProtectionDomain () {
		return target.getProtectionDomain();
	}

	/** *  Proxy to {@link java.lang.Class#toString()}. */
	public String toString () {
		return target.toString();
	}

	/** 
	 * Return the proxied class.
	 * @return the proxied class.
	 */
	public Class getProxiedClass () {
		return target;
	}

	/** 
	 * Return all known direct subclasses.
	 * @return the list of known direct subclasses.
	 */
	public Class[] getSubclasses () {
		return subclasses;
	}
}

