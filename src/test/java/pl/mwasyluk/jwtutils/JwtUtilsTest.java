package pl.mwasyluk.jwtutils;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtUtilsTest {
    Map<String, ?> defaultClaims = new HashMap<String, Object>() {{
        put(JwtUtils.USERID_CLAIM, "1241234");
        put(JwtUtils.USERNAME_CLAIM, "mwasyluk");
        put(JwtUtils.AUTHORITIES_CLAIM, new String[]{"USER", "ADMIN"});
    }};
    JwtProperties jwtProperties = new JwtProperties();
    JwtUtils jwtUtils = new JwtUtils(jwtProperties);

    @Nested
    @DisplayName("verifyToken method")
    public class VerifyTokenMethod {
        @Test
        @DisplayName("returns a valid DecodedJWT when token is valid")
        void validToken() {
            String validToken = jwtUtils.generateToken(defaultClaims);

            DecodedJWT decodedJWT = jwtUtils.verifyToken(validToken);

            assertThat(decodedJWT)
                    .isNotNull();
            assertThat(decodedJWT.getClaim("un").asString())
                    .isEqualTo("mwasyluk");
        }

        @Test
        @DisplayName("returns null when token does not contain all the required claims")
        void noRequiredClaimToken() {
            JwtUtils anotherRequiredJwtUtils =
                    new JwtUtils(jwtProperties, JwtUtils.USERNAME_CLAIM, JwtUtils.USERID_CLAIM);
            Map<String, ?> cutClaims = new HashMap<String, Object>() {{
                put(JwtUtils.USERID_CLAIM, "1241234");
                put(JwtUtils.USERNAME_CLAIM, "mwasyluk");
            }};
            String noRequiredClaimToken = anotherRequiredJwtUtils.generateToken(cutClaims);

            DecodedJWT decodedJWT = jwtUtils.verifyToken(noRequiredClaimToken);

            assertThat(decodedJWT).isNull();
        }
    }

}
