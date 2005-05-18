/***********************************************************************
 *
 * $CVSHeader$
 *
 * This file is part of WebScarab, an Open Web Application Security
 * Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2004 Rogan Dawes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Getting Source
 * ==============
 *
 * Source for this application is maintained at Sourceforge.net, a
 * repository for free software projects.
 * 
 * For details, please see http://www.sourceforge.net/projects/owasp
 *
 */

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

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.Iterator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;

/**
 *
 * @author  knoppix
 */
public class FileSystemStore implements FragmentsStore {
    
    private File _dir;
    private String _session;
    
    private static final String[] NONE = new String[0];
    
    private Map _types = new TreeMap();
    
    private Logger _logger = Logger.getLogger(getClass().getName());
    
    /** Creates a new instance of FileSystemStore */
    public FileSystemStore(File dir, String session) throws StoreException {
        _dir = dir;
        _session = session;
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
        load();
    }
    
    private void load() throws StoreException {
        File index = new File(_dir, "index");
        try {
            String type = null;
            String line;
            List list = null;
            BufferedReader br = new BufferedReader(new FileReader(index));
            while ((line = br.readLine()) != null) {
                if (line.equals("")) {
                    type = null;
                } else if (type == null) {
                    type = line;
                    list = new ArrayList();
                    _types.put(type, list);
                } else {
                    list.add(line);
                }
            }
            br.close();
        } catch (FileNotFoundException fnfe) { // nothing to do
        } catch (IOException ioe) {
            throw new StoreException("IOException reading the index: " + ioe);
        }
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
     * @param type The type of the fragment
     * @param key the key that identifies the fragment.
     * @param fragment The fragment string that should be stored.
     * @throws StoreException if there are any problems writing to the Store
     *
     * @return the position of the new key in the list, or -1 if it was already there
     */
    
    public int putFragment(String type, String key, String fragment) {
        List list = (List) _types.get(type);
        if (list == null) {
            list = new ArrayList();
            _types.put(type, list);
        }
        if (list.indexOf(key)>-1) return -1;
        list.add(key);
        File f = new File(_dir, key);
        FileWriter fw = null;
        try {
            fw = new FileWriter(f);
            fw.write(fragment);
            fw.flush();
            fw.close();
        } catch (IOException ioe) {
            _logger.warning("Error writing fragment " + key + " : " + ioe);
        }
        return list.size()-1;
    }
    
    public void flush() throws StoreException {
        File index = new File(_dir, "index");
        if (_types.size() == 0) return;
        try {
            String type = null;
            String line;
            List list;
            BufferedWriter bw = new BufferedWriter(new FileWriter(index));
            Iterator it = _types.keySet().iterator();
            while (it.hasNext()) {
                type = (String) it.next();
                bw.write(type + "\r\n");
                list = (List) _types.get(type);
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    String fragment = (String) it2.next();
                    bw.write(fragment + "\r\n");
                }
                bw.write("\r\n");
            }
            bw.close();
        } catch (FileNotFoundException fnfe) { // nothing to do
        } catch (IOException ioe) {
            throw new StoreException("IOException reading the index: " + ioe);
        }
    }
    
    public int getFragmentCount(String type) {
        List fragments = (List) _types.get(type);
        if (fragments == null) return 0;
        return fragments.size();
    }
    
    public String getFragmentKeyAt(String type, int position) {
        List fragments = (List) _types.get(type);
        if (fragments == null) return null;
        return (String) fragments.get(position);
    }
    
    public String getFragmentType(int index) {
        return ((String[]) _types.keySet().toArray(NONE))[index];
    }
    
    public int getFragmentTypeCount() {
        return _types.size();
    }
    
    public int indexOfFragment(String type, String key) {
        List list = (List) _types.get(type);
        if (list == null) return -1;
        return list.indexOf(key);
    }
    
}
