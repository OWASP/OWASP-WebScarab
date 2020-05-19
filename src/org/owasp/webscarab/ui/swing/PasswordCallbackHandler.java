package org.owasp.webscarab.ui.swing;

import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;

/**
 * Swing based password callback handler.
 *
 * @author Frank Cornelis
 */
public class PasswordCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                JPasswordField passwordField = new JPasswordField(20);
                int result = JOptionPane.showConfirmDialog(null, passwordField, "Enter password", JOptionPane.OK_CANCEL_OPTION);
                if (result == JOptionPane.OK_OPTION) {
                    char[] password = passwordField.getPassword();
                    passwordCallback.setPassword(password);
                } else {
                    passwordCallback.clearPassword();
                }
            }
        }
    }
}
