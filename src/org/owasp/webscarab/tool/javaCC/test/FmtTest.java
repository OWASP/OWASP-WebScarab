/// Note: Format.java is considered working properly if it
/// successfully converts Test.java to an output that nearly
/// exactly matches Test.formatted (only CVS tags are allowed
/// to differ).
package org.owasp.webscarab.tool.javaCC.test;

import java.io.File;
import java.io.FileWriter;
import java.util.*;

/**
 * <TODO description>
 *
 * @since release <RELEASE>
 * @version release <RELEASE><br />$Revision: 1.1 $ $Author: istr $
 * @author <AUTHOR>
 */
public final class FmtTest 
    extends HashMap 
    implements Observer 
{
    private transient float thing;
    protected int a;
    
    FmtTest ( int op ) {}
    
    FmtTest () {
        this( 0 );
    }

    int get () {
        return a;
    }

    public void update ( Observable o, Object arg ) {
        boolean thing = false;
        int[] g = new int[3];
        for ( int i = 0; i < 10; ++i ) {
            ++i;
        }
        if ( !thing && 0 == g[ 1 ] )
            get();
        if ( g[ 2 ] == 1 ) {
            get();
            g[ 1 ] = 4;
            g[ 0 ] = get();
        } else {
            String[] fr = { "mmdfwe", "jkfdljal", "akldjfl", "jkldjfl", 
                            "skdjfl" };
        }
        if ( true ) {
            thing = true;
        } else {
            thing = false;
        }
        if ( true ) {
            thing = true;
        } else {
            thing = false;
        }
        if ( true )
            thing = true;
        else
            thing = false;
        if ( true )
            thing = true;
        else 
        if ( false )
            thing = false;
        else
            thing = true;
        for ( int i = 0; i < 4; i++ ) 
            if ( 3 == i )
                g[ 2 ] = 5;
            else
                g[ 1 ] = i;
        do 
            thing = !thing;
        while ( !thing );
        while ( thing ) 
            if ( 3 == g[ 2 ] )
                thing = what( g[ 1 ] );
        do {
            thing = !thing;
            g[ 0 ] = g[ 0 ] + (thing
                              ? 1
                              : 0);
        } while ( !thing );
        while ( !thing ) {
            g[ 0 ] = 1;
            thing = !thing;
        }
    }

    /** Returns a senseless value.
  * @param s the int value to check. 
* @return false if s <= 0 else true
   */
    boolean what ( int s ) {
        return (s <= 0)
               ? false
               : true;
    }

    strictfp double result () {
        return 0.0;
    }
}

