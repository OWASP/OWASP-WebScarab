/*
 * Script.java
 *
 * Created on 07 January 2005, 04:30
 */

package org.owasp.webscarab.plugin;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

/**
 *
 * @author  rogan
 */
public class Script {
    
    private File _file;
    private String _script;
    private long _lastModified;
    private boolean _enabled;
    private String _language = null;
    
    /** Creates a new instance of Script */
    public Script(File file) throws IOException {
        _file = file;
        reload();
        _enabled = false;
    }
    
    public void reload() throws IOException {
        FileReader fr = null;
        try {
            fr = new FileReader(_file);
            int got;
            char[] buff = new char[1024];
            StringBuffer script = new StringBuffer();
            while ((got=fr.read(buff))>0) {
                script.append(buff,0,got);
            }
            _script = script.toString();
            _lastModified = _file.lastModified();
        } catch (IOException ioe) {
            _enabled = false;
            _script = "";
            throw ioe;
        } finally {
            if (fr!=null) fr.close();
        }
    }
    
    public boolean isEnabled() {
        return _enabled;
    }
    
    public void setEnabled(boolean enabled) {
        _enabled = enabled;
    }
    
    public File getFile() {
        return _file;
    }
    
    public String getScript() {
        return _script;
    }
    
    public void setScript(String script) throws IOException {
        _script = script;
        FileWriter fw = null;
        try { 
            fw = new FileWriter(_file);
            fw.write(_script);
        } catch (IOException ioe) {
            _script = null;
            _lastModified = -1;
            _language = null;
            _enabled = false;
            throw ioe;
        } finally {
            if (fw != null) fw.close();
        }
    }
    
    public long getLastModified() {
        return _lastModified;
    }
    
    public String getLanguage() {
        return _language;
    }
    
    public void setLanguage(String language) {
        _language = language;
    }
}
