/*
 * ReentrantReaderPreferenceReadWriteLock.java
 *
 * Created on September 8, 2004, 7:38 AM
 */

package org.owasp.webscarab.util;

import EDU.oswego.cs.dl.util.concurrent.ReentrantWriterPreferenceReadWriteLock;

import java.util.Iterator;

/** Provides an implementation of a reentrant Read/Write lock that gives preference
 * to readers, rather than writers. This makes sense in the context of the webscarab
 * model because updates are fired with a read lock held, we want our listeners
 * to be able to get back into the model to perform other reads, BEFORE any other
 * writes are permitted.
 *
 * @author  rogan
 */
public class ReentrantReaderPreferenceReadWriteLock extends ReentrantWriterPreferenceReadWriteLock {
    
    /** Creates a new instance of ReentrantReaderPreferenceReadWriteLock */
    public ReentrantReaderPreferenceReadWriteLock() {
        super();
    }
    
    
    /**
     * Provides an implementation of a reentrant Read/Write lock that gives preference
     * to readers, rather than writers. This makes sense in the context of the model,
     * because updates are fired with a read lock held, we generally want our listeners
     * to be able to get back into the model to perform other reads, BEFORE any other
     * writes are permitted.
     * @return true when there are no active writers, or the active writer is the current thread
     */
    protected boolean allowReader() {
        return activeWriter_ == null || activeWriter_ == Thread.currentThread();
    }
    
    public void debug() {
        Iterator it = readers_.keySet().iterator();
        System.err.println("Readers:");
        while(it.hasNext()) {
            Object key = it.next();
            Object value = readers_.get(key);
            System.err.println(key + " : " + value);
        }
        System.err.println("Done");
        System.err.println("Writer thread:");
        System.err.println(activeWriter_.getName());
        System.err.println("Stack Trace:");
        activeWriter_.dumpStack();
    }
    
}
