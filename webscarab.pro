-injars webscarab.jar
-injars lib/concurrent.jar
-injars lib/bsh-2.0b1.jar
-injars lib/htmlparser.jar
-injars lib/jcommon-0.8.7.jar
-injars lib/jfreechart-0.9.12.jar

-libraryjars lib/bsf-2.3.0.jar
-libraryjars /opt/eclipse/plugins/org.eclipse.tomcat_4.1.30/servlet.jar

-verbose
-ignorewarnings
-dontoptimize
-dontobfuscate
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses


# Keep - Applications. Keep all application classes that have a main method.
-keepclasseswithmembers public class org.owasp.webscarab.ui.swing.Main {
    public static void main(java.lang.String[]);
}

-keep class * extends org.owasp.webscarab.ui.swing.editors.ByteArrayEditor

# Keep names - Native method names. Keep all native class/method names.
-keepclasseswithmembernames class * {
    native <methods>;
}
