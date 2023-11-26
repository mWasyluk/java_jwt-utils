package pl.mwasyluk.jwtutils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Instant;
import java.util.*;

public final class JwtUtils {
    private static final Logger log = LogManager.getLogger("JwtUtilsLogger");

    public static final String USERID_CLAIM = "uid";
    public static final String USERNAME_CLAIM = "un";
    public static final String AUTHORITIES_CLAIM = "auths";

    private final Algorithm jwtAlgorithm;
    private final String[] requiredClaims;
    private final JwtProperties jwtProperties;

    public JwtUtils(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.jwtAlgorithm = Algorithm.HMAC256(jwtProperties.getSecret());
        this.requiredClaims = new String[]{USERID_CLAIM, USERNAME_CLAIM, AUTHORITIES_CLAIM};
    }

    public JwtUtils(JwtProperties jwtProperties, String... requiredClaims) {
        this.jwtProperties = jwtProperties;
        this.jwtAlgorithm = Algorithm.HMAC256(jwtProperties.getSecret());
        this.requiredClaims = requiredClaims;
    }

    public String[] getRequiredClaimsArray() {
        return requiredClaims;
    }

    public JwtProperties getJwtProperties() {
        return jwtProperties;
    }

    // provide a basic verification configuration
    private Verification basicVerification() {
        Verification verification = JWT
                .require(jwtAlgorithm)
                .withIssuer(jwtProperties.getIssuer())
                .acceptExpiresAt(0);

        for (String claim : requiredClaims) {
            verification.withClaimPresence(claim);
        }

        return verification;
    }

    // retrieve a username from the given token
    public String extractUsername(String token) {
        DecodedJWT decodedJWT = verifyToken(token);

        if (decodedJWT == null) {
            return "";
        }

        return decodedJWT.getClaim(USERNAME_CLAIM).asString();
    }

    public Optional<Claim> extractClaim(String token, String key) {
        DecodedJWT decodedJWT = verifyToken(token);

        if (decodedJWT == null) {
            return Optional.empty();
        }

        Claim claim = decodedJWT.getClaim(key);
        if (claim.isMissing()) {
            return Optional.empty();
        }

        return Optional.of(claim);
    }

    public Map<String, Claim> extractAllClaims(String token) {
        DecodedJWT decodedJWT = verifyToken(token);

        if (decodedJWT == null) {
            return new HashMap<>();
        }

        return decodedJWT.getClaims();
    }

    // verify the given token
    public DecodedJWT verifyToken(String token) {
        JWTVerifier jwtVerifier = basicVerification()
                .build();

        try {
            return jwtVerifier.verify(token);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            return null;
        }
    }

    // generate JWT based on the given claims
    public String generateToken(Map<String, ?> claims) {
        // ensure that the given claims contain each of the required keys
        if (!claims.keySet().containsAll(Arrays.asList(requiredClaims))) {
            log.error("Cannot generate a new token without the required claims.");
            return null;
        }

        log.info("Generating a new token...");
        return JWT.create()
                .withIssuer(jwtProperties.getIssuer())
                .withPayload(claims)
                .withExpiresAt(Instant.now().plusSeconds(jwtProperties.getExpirationTimeSec()))
                .withIssuedAt(Instant.now())
                .sign(jwtAlgorithm);
    }

    public String refreshToken(String token) {
        DecodedJWT decodedJWT = verifyToken(token);

        if (decodedJWT == null) {
            return null;
        }

        String payloadJson = new String(Base64.getDecoder()
                .decode(decodedJWT.getPayload().getBytes()));

        return JWT.create()
                .withPayload(payloadJson)
                .withExpiresAt(Instant.now().plusSeconds(jwtProperties.getExpirationTimeSec()))
                .withIssuedAt(Instant.now())
                .sign(jwtAlgorithm);
    }
}
