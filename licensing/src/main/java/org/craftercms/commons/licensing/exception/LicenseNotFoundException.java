package org.craftercms.commons.licensing.exception;

public class LicenseNotFoundException extends Exception {

    private static final long serialVersionUID = 4015174714566914121L;

    public LicenseNotFoundException() {
    }

    public LicenseNotFoundException(String message) {
        super(message);
    }

    public LicenseNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public LicenseNotFoundException(Throwable cause) {
        super(cause);
    }

    public LicenseNotFoundException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
