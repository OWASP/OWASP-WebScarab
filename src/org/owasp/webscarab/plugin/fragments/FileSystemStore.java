/*
 * FileSystemStore.java
 *
 * Created on September 14, 2004, 4:11 PM
 */

package org.owasp.webscarab.plugin.fragments;

import org.owasp.webscarab.model.StoreException;
import org.owasp.webscarab.util.Encoding;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileNotFoundException;

import java.util.logging.Logger;

/**
 *
 * @author  knoppix
 */
public class FileSystemStore implements FragmentsStore {
    
    private File _dir;
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of FileSystemStore */
    public FileSystemStore(File dir) throws StoreException {
        _dir = dir;
        create();
    }
    
    private void create() throws StoreException {
        if (! _dir.exists()) {
            throw new StoreException( _dir + " does not exist!");
        }
        _dir = new File(_dir,"fragments");
        if (!_dir.exists() && !_dir.mkdirs()) {
            throw new StoreException("Couldn't create directory " + _dir);
        } else if (!_dir.isDirectory()) {
            throw new StoreException(_dir + " exists, and is not a directory!");
        }
    }
    
    private void load() throws StoreException {
        // nothing to load - mostly in the SiteModel
    }
    
    /** retrieves a saved text fragment
     * @param key The key used previously to save the fragment
     * @return A String containing the fragment
     * @throws StoreException if there are any problems reading from the Store
     *
     */
    public String getFragment(String key) {
        File f = new File(_dir, key);
        FileReader fr = null;
        try {
            fr = new FileReader(f);
        } catch (FileNotFoundException fnfe) {
            _logger.warning("Error reading fragment '" + key + "' : " + fnfe);
            return "";
        }
        StringBuffer sb = new StringBuffer();
        char[] buf = new char[1024];
        int got = 0;
        try {
            while ((got=fr.read(buf))>0) {
                sb.append(buf,0,got);
            }
            fr.close();
        } catch (IOException ioe) {
            _logger.warning("Error reading fragment '" + key + "' : " + ioe);
        }
        return sb.toString();
    }
    
    /** Stores a text fragment for future retrieval
     * @param key a string which can be used to request the fragment in the future
     * @param fragment The fragment string that should be stored.
     * @throws StoreException if there are any problems writing to the Store
     *
     */
    
    public String putFragment(String fragment) {
        String key = Encoding.hashMD5(fragment);
        File f = new File(_dir, key);
        FileWriter fw = null;
        try {
            if (f.exists()) {
                return key;
            }
            fw = new FileWriter(f);
            fw.write(fragment);
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            _logger.warning("Error writing fragment " + key + " : " + ioe);
        }
        return key;
    }
    
    public void flush() throws StoreException {
        // nothing to do, we write them out as we see them
    }
    
}
