/*
 * WebSPHINX web crawling toolkit
 * Copyright (C) 1998,1999 Carnegie Mellon University 
 * 
 * This library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Library
 * General Public License as published by the Free Software 
 * Foundation, version 2.
 *
 * WebSPHINX homepage: http://www.cs.cmu.edu/~rcm/websphinx/
 */
package org.owasp.webscarab.spider;

import java.net.URL;
import java.net.URLConnection;
import java.io.File;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import netscape.security.PrivilegeManager;
import netscape.security.ForbiddenTargetException;

public class Netscape4Policy extends SecurityPolicy {

    private boolean isLocalURL (URL url) {
        return (url.getProtocol().equals ("file")
                     && url.getHost().equals (""));
    }

    public URLConnection openConnection (URL url) throws IOException {
        try {                             
            PrivilegeManager.enablePrivilege ("UniversalConnectWithRedirect");
            if (isLocalURL (url))
                PrivilegeManager.enablePrivilege ("UniversalFileRead");
        } catch (ForbiddenTargetException e) {
          throw new IOException ("connection forbidden");
        }

        return super.openConnection (url);
    }

    public URLConnection openConnection (Link link) throws IOException {
        try {
            PrivilegeManager.enablePrivilege ("UniversalConnectWithRedirect");
        } catch (ForbiddenTargetException e) {
          throw new IOException ("connection forbidden");
        }

        if (isLocalURL (link.getURL()))
          PrivilegeManager.enablePrivilege ("UniversalFileRead");
        return super.openConnection (link);
    }

  public InputStream readFile (File file) throws IOException {
    try {
      PrivilegeManager.enablePrivilege("UniversalFileRead");
    } catch (ForbiddenTargetException e) {
      throw new IOException ("file read forbidden");
    }

    return super.readFile (file);
  }

  public OutputStream writeFile (File file, boolean append) throws IOException {
    try {
      PrivilegeManager.enablePrivilege("UniversalFileWrite");
    } catch (ForbiddenTargetException e) {
      throw new IOException ("file write forbidden");
    }

    return super.writeFile (file, append);
  }

  public RandomAccessFile readWriteFile (File file) throws IOException {
    try {
      PrivilegeManager.enablePrivilege("UniversalFileWrite");
      PrivilegeManager.enablePrivilege("UniversalFileRead");
    } catch (ForbiddenTargetException e) {
      throw new IOException ("file read/write forbidden");
    }
    
    return super.readWriteFile (file);
  }

    public void makeDir (File file) throws IOException {
        try {
          PrivilegeManager.enablePrivilege("UniversalFileWrite");
          PrivilegeManager.enablePrivilege("UniversalFileRead");
            // mkdirs needs UniversalFileRead to check whether a 
            // directory already exists (I guess)
        } catch (ForbiddenTargetException e) {
          throw new IOException ("make-directory forbidden");
        }
        
        super.makeDir (file);
    }

    
  public File makeTemporaryFile (String basename, String extension) {
    try {
      PrivilegeManager.enablePrivilege("UniversalFileRead"); 
            // need UniversalFileRead to check whether a filename
            // already exists
            // FIX: should I bother with that check?
    } catch (ForbiddenTargetException e) {
      throw new SecurityException ("temp file check forbidden");
    }
      
    return super.makeTemporaryFile (basename, extension);
  }
}
