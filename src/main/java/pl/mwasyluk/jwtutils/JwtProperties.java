package pl.mwasyluk.jwtutils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static pl.mwasyluk.jwtutils.DefaultJwtProperties.*;

public final class JwtProperties {
    private final static Logger log = LogManager.getLogger("JwtPropertiesLogger");

    public static final String EXPIRATION_TIME_SEC_PROP_NAME = "jwt.expiration-time-sec";
    public static final String ISSUER_PROP_NAME = "jwt.issuer";
    public static final String SECRET_PROP_NAME = "jwt.secret";

    private String issuer;
    private String secret;
    private Long expirationTimeSec;

    JwtProperties() {
        loadProperties();
    }

    public JwtProperties reload() {
        this.loadProperties();
        return this;
    }

    private void loadProperties() {
        String secret = System.getProperty(SECRET_PROP_NAME);
        String issuer = System.getProperty(ISSUER_PROP_NAME);

        if (secret == null || secret.isEmpty()) {
            log.warn("Provided " + SECRET_PROP_NAME + " is not a valid property value.");
            log.warn("Setting " + SECRET_PROP_NAME + " as " + SECRET);
            this.secret = SECRET;
        } else {
            this.secret = secret;
        }

        if (issuer == null || issuer.isEmpty()) {
            log.warn("Provided " + ISSUER_PROP_NAME + " is not a valid property value.");
            log.warn("Setting " + ISSUER_PROP_NAME + " as " + ISSUER);
            this.issuer = ISSUER;
        } else {
            this.issuer = issuer;
        }

        String expTimeString = System.getProperty(EXPIRATION_TIME_SEC_PROP_NAME);

        if (expTimeString == null || expTimeString.isEmpty()) {
            log.warn("The " + EXPIRATION_TIME_SEC_PROP_NAME + " property value has not been set.");
            log.warn("Setting " + EXPIRATION_TIME_SEC_PROP_NAME + " as " + EXPIRATION_TIME_SEC);
            this.expirationTimeSec = EXPIRATION_TIME_SEC;
        } else {
            try {
                this.expirationTimeSec = Long.parseLong(expTimeString);
            } catch (NumberFormatException ex) {
                log.warn("The " + EXPIRATION_TIME_SEC_PROP_NAME + " property value is not a valid Long value.");
                log.warn("Setting " + EXPIRATION_TIME_SEC_PROP_NAME + " as " + EXPIRATION_TIME_SEC);
                this.expirationTimeSec = EXPIRATION_TIME_SEC;
            }
        }
    }

    public Long getExpirationTimeSec() {
        return expirationTimeSec;
    }

    String getIssuer() {
        return issuer;
    }

    String getSecret() {
        return secret;
    }
}
