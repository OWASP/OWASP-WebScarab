/* ****************************************************************
 * Compile this as a DLL using MingGW:
 * gcc -mno-cygwin -Wall -D_JNI_IMPLEMENTATION_ -Wl,--kill-at -I$JAVA_HOME/include -I$JAVA_HOME/include/win32 -Wl,--add-stdcall-alias -shared -o W32WinInet.dll W32WinInet.c -lwininet
 * 
 * for testing, compile as a standalone executable using MinGW. Only the setProxy function will work, of course.
 * gcc -mno-cygwin -Wall -D_JNI_IMPLEMENTATION_ -Wl,--kill-at -I$JAVA_HOME/include -I$JAVA_HOME/include/win32 -Wl,--add-stdcall-alias -o W32WinInet.exe W32WinInet.c -lwininet
 *
 * ****************************************************************/

#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wininet.h>

/* additional definitions that do not exist in the standard Cygwin wininet.h
 * They could be removed if they were folded back into the Cygwin/MinGW distribution
 */
 
//
// Options used in INTERNET_PER_CONN_OPTON struct
//
#define INTERNET_PER_CONN_FLAGS                         1
#define INTERNET_PER_CONN_PROXY_SERVER                  2
#define INTERNET_PER_CONN_PROXY_BYPASS                  3
#define INTERNET_PER_CONN_AUTOCONFIG_URL                4
#define INTERNET_PER_CONN_AUTODISCOVERY_FLAGS           5

//
// PER_CONN_FLAGS
//
#define PROXY_TYPE_DIRECT                               0x00000001   // direct to net
#define PROXY_TYPE_PROXY                                0x00000002   // via named proxy
#define PROXY_TYPE_AUTO_PROXY_URL                       0x00000004   // autoproxy URL
#define PROXY_TYPE_AUTO_DETECT                          0x00000008   // use autoproxy detection

//
// PER_CONN_AUTODISCOVERY_FLAGS
//
#define AUTO_PROXY_FLAG_USER_SET                        0x00000001   // user changed this setting
#define AUTO_PROXY_FLAG_ALWAYS_DETECT                   0x00000002   // force detection even when its not needed
#define AUTO_PROXY_FLAG_DETECTION_RUN                   0x00000004   // detection has been run
#define AUTO_PROXY_FLAG_MIGRATED                        0x00000008   // migration has just been done 
#define AUTO_PROXY_FLAG_DONT_CACHE_PROXY_RESULT         0x00000010   // don't cache result of host=proxy name
#define AUTO_PROXY_FLAG_CACHE_INIT_RUN                  0x00000020   // don't initalize and run unless URL expired
#define AUTO_PROXY_FLAG_DETECTION_SUSPECT               0x00000040   // if we're on a LAN & Modem, with only one IP, bad?!?



#define INTERNET_OPTION_PER_CONNECTION_OPTION    75

typedef struct {
  DWORD dwOption;
  union {
    DWORD dwValue;
    LPTSTR pszValue;
    FILETIME ftValue;
  } Value;
} INTERNET_PER_CONN_OPTION, 
*LPINTERNET_PER_CONN_OPTION;

typedef struct {
  DWORD dwSize;
  LPTSTR pszConnection;
  DWORD dwOptionCount;
  DWORD dwOptionError;
  LPINTERNET_PER_CONN_OPTION pOptions;
} INTERNET_PER_CONN_OPTION_LIST, 
*LPINTERNET_PER_CONN_OPTION_LIST;

/* end of extra WinInet.h definitions. */

#include <jni.h>
#include "org_owasp_webscarab_util_W32WinInet.h"

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    testLibraryLoad
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_owasp_webscarab_util_W32WinInet_testLibraryLoad
  (JNIEnv *env, jclass class) {
    return 1;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    getInternetPerConnFlags
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_owasp_webscarab_util_W32WinInet_getInternetPerConnFlags
  (JNIEnv *env, jclass class) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[1];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_FLAGS;
    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 1;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
        printf("InternetQueryOption failed! (%ld)\n", GetLastError());
    
    return Option[0].Value.dwValue;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    getAutoDiscoveryFlags
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_owasp_webscarab_util_W32WinInet_getAutoDiscoveryFlags
  (JNIEnv *env, jclass class) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[1];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_AUTODISCOVERY_FLAGS;
    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 1;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
        printf("InternetQueryOption failed! (%ld)\n", GetLastError());
    
    return Option[0].Value.dwValue;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    getAutoConfigUrl
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_owasp_webscarab_util_W32WinInet_getAutoConfigUrl
  (JNIEnv *env, jclass class) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[1];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 1;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
        printf("InternetQueryOption failed! (%ld)\n", GetLastError());
    
    jstring ret = NULL;
    if (Option[0].Value.pszValue != NULL) {
        ret = (*env)->NewStringUTF(env, Option[0].Value.pszValue);
        GlobalFree(Option[0].Value.pszValue);
    }
    return ret;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    getProxyServer
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_owasp_webscarab_util_W32WinInet_getProxyServer
  (JNIEnv *env, jclass class) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[1];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 1;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
        printf("InternetQueryOption failed! (%ld)\n", GetLastError());
    
    jstring ret = NULL;
    if (Option[0].Value.pszValue != NULL) {
        ret = (*env)->NewStringUTF(env, Option[0].Value.pszValue);
        GlobalFree(Option[0].Value.pszValue);
    }
    return ret;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    getProxyBypass
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_owasp_webscarab_util_W32WinInet_getProxyBypass
  (JNIEnv *env, jclass class) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[1];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 1;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetQueryOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, &nSize))
        printf("InternetQueryOption failed! (%ld)\n", GetLastError());
    
    jstring ret = NULL;
    if (Option[0].Value.pszValue != NULL) {
        ret = (*env)->NewStringUTF(env, Option[0].Value.pszValue);
        GlobalFree(Option[0].Value.pszValue);
    }
    return ret;
}

int setProxy(long perConnFlags, char* proxyServer, char* proxyBypass) {
    INTERNET_PER_CONN_OPTION_LIST    List;
    INTERNET_PER_CONN_OPTION         Option[3];
    unsigned long                    nSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);

    Option[0].dwOption = INTERNET_PER_CONN_FLAGS;
    Option[0].Value.dwValue = perConnFlags;

    Option[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    Option[1].Value.pszValue = proxyServer;

    Option[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    Option[2].Value.pszValue = proxyBypass;

    List.dwSize = sizeof(INTERNET_PER_CONN_OPTION_LIST);
    List.pszConnection = NULL;
    List.dwOptionCount = 3;
    List.dwOptionError = 0;
    List.pOptions = Option;

    if(!InternetSetOption(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &List, nSize))
        return GetLastError(); // we should throw an exception here, maybe?

    //The connection settings for other instances of Internet Explorer.
    if (!InternetSetOption(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0))
        return GetLastError(); // we should throw an exception here, maybe?
        
    //The connection settings for other instances of Internet Explorer.
    // if (!InternetSetOption(NULL, INTERNET_OPTION_REFRESH, NULL, 0))
    //     return GetLastError(); // we should throw an exception here, maybe?

    return 0;
}

/*
 * Class:     org_owasp_webscarab_util_W32WinInet
 * Method:    setProxy
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_owasp_webscarab_util_W32WinInet_setProxy
  (JNIEnv *env, jclass class, jlong perConnFlags, jstring proxyServer, jstring proxyBypass) {

    char *ps = NULL;
    if (proxyServer != NULL)
        ps = (LPTSTR) (*env)->GetStringUTFChars(env, proxyServer, 0);
    
    char *pb = NULL;
    if (proxyBypass != NULL)
        pb = (LPTSTR) (*env)->GetStringUTFChars(env, proxyBypass, 0);

    int ret = setProxy(perConnFlags, ps, pb);
    
    if (ps != NULL) 
        (*env)->ReleaseStringUTFChars(env, proxyServer, ps);
    if (pb != NULL) 
        (*env)->ReleaseStringUTFChars(env, proxyBypass, pb);
    
    return ret;
}

int main(int argc, char* argv[]) {
    printf("Result is %d\n", setProxy(PROXY_TYPE_PROXY, "localhost:3128", NULL));
    return 0;
}
