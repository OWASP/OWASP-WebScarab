#!/bin/bash

TIMESTAMP=`cat timestamp`
cat << FILES > filelist.txt
(N)lib/htmlparser.jar|lib/htmlparser.jar|
(N)lib/owasp.jar|lib/owasp.jar|
(N)webscarab.jar|webscarab.jar|
{
  JavaLauncher
  ScriptName=webscarab
  Class=org.owasp.webscarab.ui.swing.WebScarab
  ClassPath=webscarab.jar
}
FILES
cat webscarab.vai | sed "s/TIMESTAMP/$TIMESTAMP/g" > webscarab.vai.tmp
java -cp lib/vainstall.jar com.memoire.vainstall.VAInstall webscarab.vai.tmp
rm webscarab.vai.tmp
rm filelist.txt
mv Installer.jar WebScarab-$TIMESTAMP.jar

