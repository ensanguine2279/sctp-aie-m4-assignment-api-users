package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

/**
 * Plain unit tests: no Spring context. JwtService takes its secret and expiry
 * through the constructor, so it can be created directly.
 */
class JwtServiceTest {

    private static final String SECRET = "test-secret-key-that-is-at-least-32-bytes-long";
    private static final String OTHER_SECRET = "a-completely-different-secret-key-of-32-plus-bytes";
    private static final long EXPIRATION_MS = 3_600_000L; // 1 hour

    private final JwtService jwtService = new JwtService(SECRET, EXPIRATION_MS);

    // ---------- helpers ----------

    /**
     * Builds a token with the SAME secret as jwtService, for crafting unusual
     * claims.
     */
    private JwtBuilder baseBuilder() {
        return Jwts.builder()
                .setSubject("alice01")
                .setExpiration(new Date(System.currentTimeMillis() + 60_000));
    }

    private String sign(JwtBuilder builder) {
        return builder
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    private Reason reasonOf(Executable executable) {
        return assertThrows(InvalidTokenException.class, executable).getReason();
    }

    // ---------- generate + parse round trip ----------

    @Test
    @DisplayName("generateToken produces a token whose claims round-trip")
    void generateToken_roundTrip_returnsSameClaims() {
        String token = jwtService.generateToken("alice01", List.of("ROLE_USER", "ROLE_ADMIN"));

        ClaimsDto claims = jwtService.extractClaims(token);

        assertThat(claims.username()).isEqualTo("alice01");
        assertThat(claims.roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("generateToken sets the expiry from the configured duration")
    void generateToken_setsExpiryFromConfiguration() {
        long before = System.currentTimeMillis();
        String token = jwtService.generateToken("alice01", List.of("ROLE_USER"));
        long after = System.currentTimeMillis();

        long expiration = jwtService.extractClaims(token).expiration();

        // JWT stores whole seconds, so the value can be up to 1000 ms below the exact
        // expiry.
        assertThat(expiration).isBetween(before + EXPIRATION_MS - 1000, after + EXPIRATION_MS);
    }

    @Test
    @DisplayName("generateToken with no roles yields an empty role list")
    void generateToken_noRoles_returnsEmptyRoles() {
        String token = jwtService.generateToken("alice01", List.of());

        assertThat(jwtService.extractClaims(token).roles()).isEmpty();
    }

    // ---------- role filtering ----------

    @Test
    @DisplayName("roles without the ROLE_ prefix are dropped")
    void extractClaims_dropsRolesWithoutPrefix() {
        String token = jwtService.generateToken("alice01", List.of("ROLE_USER", "ADMIN", "SCOPE_read"));

        assertThat(jwtService.extractClaims(token).roles()).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("non-string entries in the roles claim are ignored")
    void extractClaims_ignoresNonStringRoles() {
        String token = sign(baseBuilder().claim("roles", List.of("ROLE_USER", 42, "ROLE_ADMIN")));

        assertThat(jwtService.extractClaims(token).roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("a missing roles claim yields an empty list")
    void extractClaims_missingRolesClaim_returnsEmptyList() {
        String token = sign(baseBuilder());

        assertThat(jwtService.extractClaims(token).roles()).isEmpty();
    }

    @Test
    @DisplayName("a roles claim that is not a list yields an empty list")
    void extractClaims_rolesClaimNotAList_returnsEmptyList() {
        String token = sign(baseBuilder().claim("roles", "ROLE_ADMIN"));

        assertThat(jwtService.extractClaims(token).roles()).isEmpty();
    }

    // ---------- rejected tokens ----------

    @Test
    @DisplayName("an expired token is rejected with EXPIRED")
    void extractClaims_expiredToken_throwsExpired() {
        JwtService shortLived = new JwtService(SECRET, -5_000L); // already expired when issued
        String token = shortLived.generateToken("alice01", List.of("ROLE_USER"));

        assertThat(reasonOf(() -> jwtService.extractClaims(token))).isEqualTo(Reason.EXPIRED);
    }

    @Test
    @DisplayName("a token signed with a different secret is rejected with BAD_SIGNATURE")
    void extractClaims_wrongSecret_throwsBadSignature() {
        JwtService otherIssuer = new JwtService(OTHER_SECRET, EXPIRATION_MS);
        String token = otherIssuer.generateToken("alice01", List.of("ROLE_USER"));

        assertThat(reasonOf(() -> jwtService.extractClaims(token))).isEqualTo(Reason.BAD_SIGNATURE);
    }

    @Test
    @DisplayName("a token with a forged payload and the original signature is rejected (role escalation attempt)")
    void extractClaims_tamperedPayload_throwsBadSignature() {
        String token = jwtService.generateToken("alice01", List.of("ROLE_USER"));
        String[] parts = token.split("\\.");

        String forgedJson = "{\"sub\":\"alice01\",\"roles\":[\"ROLE_ADMIN\"],\"exp\":4102444800}";
        String forgedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(forgedJson.getBytes(StandardCharsets.UTF_8));
        String forgedToken = parts[0] + "." + forgedPayload + "." + parts[2];

        assertThat(reasonOf(() -> jwtService.extractClaims(forgedToken))).isEqualTo(Reason.BAD_SIGNATURE);
    }

    @Test
    @DisplayName("an unsigned token (alg none) is rejected")
    void extractClaims_unsignedToken_isRejected() {
        String unsigned = baseBuilder().claim("roles", List.of("ROLE_ADMIN")).compact();

        assertThat(reasonOf(() -> jwtService.extractClaims(unsigned))).isEqualTo(Reason.MALFORMED);
    }

    @Test
    @DisplayName("a validly signed token with no expiry is rejected with MALFORMED")
    void extractClaims_missingExpiry_throwsMalformed() {
        // Signed with the correct secret, but no exp claim (e.g. issued by another
        // service).
        String token = sign(Jwts.builder().setSubject("alice01").claim("roles", List.of("ROLE_USER")));

        assertThat(reasonOf(() -> jwtService.extractClaims(token))).isEqualTo(Reason.MALFORMED);
    }

    @Test
    @DisplayName("a validly signed token with a missing or blank subject is rejected with MALFORMED")
    void extractClaims_missingSubject_throwsMalformed() {
        Date expiry = new Date(System.currentTimeMillis() + 60_000);
        String noSubject = sign(Jwts.builder().setExpiration(expiry));
        String blankSubject = sign(Jwts.builder().setSubject("   ").setExpiration(expiry));

        assertThat(reasonOf(() -> jwtService.extractClaims(noSubject))).isEqualTo(Reason.MALFORMED);
        assertThat(reasonOf(() -> jwtService.extractClaims(blankSubject))).isEqualTo(Reason.MALFORMED);
    }

    @Test
    @DisplayName("a malformed token is rejected with MALFORMED")
    void extractClaims_malformedToken_throwsMalformed() {
        assertThat(reasonOf(() -> jwtService.extractClaims("not-a-jwt"))).isEqualTo(Reason.MALFORMED);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "   " })
    @DisplayName("a null, empty or blank token is rejected with EMPTY")
    void extractClaims_missingToken_throwsEmpty(String token) {
        assertThat(reasonOf(() -> jwtService.extractClaims(token))).isEqualTo(Reason.EMPTY);
    }

    // ---------- constructor / secret validation ----------

    @Test
    @DisplayName("a secret shorter than 32 bytes stops the service from being created")
    void constructor_weakSecret_throwsIllegalState() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new JwtService("too-short-secret", EXPIRATION_MS));

        assertThat(ex.getMessage()).contains("32 bytes");
    }

    @Test
    @DisplayName("a secret of exactly 32 bytes is accepted")
    void constructor_minimumLengthSecret_isAccepted() {
        JwtService service = new JwtService("a".repeat(32), EXPIRATION_MS);

        String token = service.generateToken("alice01", List.of("ROLE_USER"));

        assertThat(service.extractClaims(token).username()).isEqualTo("alice01");
    }
}