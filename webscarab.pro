-injars /home/rogan/workspace/webscarab/webscarab.jar
-injars /home/rogan/workspace/webscarab/lib/concurrent.jar
-injars /home/rogan/workspace/webscarab/lib/bsh-2.0b1.jar
-injars /home/rogan/workspace/webscarab/lib/htmlparser.jar
-injars /home/rogan/workspace/webscarab/lib/jcommon-0.8.7.jar
-injars /home/rogan/workspace/webscarab/lib/jfreechart-0.9.12.jar

-libraryjars /opt/j2sdk1.4.2_05/jre/lib/rt.jar
-libraryjars /opt/j2sdk1.4.2_05/jre/lib/jsse.jar
-libraryjars /home/rogan/workspace/webscarab/lib/bsf-2.3.0.jar
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
