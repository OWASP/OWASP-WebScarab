package org.owasp.webscarab.httpclient;

import java.security.KeyStore;
import org.owasp.webscarab.ui.swing.PasswordCallbackHandler;

/**
 *
 * @author Frank Cornelis
 */
public class Pkcs11LoadStoreParameter implements KeyStore.LoadStoreParameter {

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return new KeyStore.CallbackHandlerProtection(new PasswordCallbackHandler());
    }
}
