package sg.edu.ntu.taskflow_api.users.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

class JwtServiceTest {

    private static final String ISSUER = "users-service";
    private static final String AUDIENCE = "tasks-api";
    private static final long EXPIRATION_MS = 15 * 60 * 1000L;

    private static KeyPair keyPair;
    private static KeyPair otherKeyPair;

    @TempDir
    Path tmp;

    private JwtService service;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();
        otherKeyPair = gen.generateKeyPair();
    }

    @BeforeEach
    void setUp() throws IOException {
        service = newService(EXPIRATION_MS, ISSUER, AUDIENCE);
    }

    // ---------- helpers ----------

    private JwtService newService(long expirationMs, String issuer, String audience) throws IOException {
        Path pem = writePrivatePem(tmp.resolve("private-" + System.nanoTime() + ".pem"), keyPair);
        return new JwtService(pem.toString(), expirationMs, issuer, audience);
    }

    private static Path writePrivatePem(Path file, KeyPair pair) throws IOException {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(pair.getPrivate().getEncoded());
        return Files.writeString(file,
                "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n");
    }

    /** Builds a token by hand so tests can omit or alter individual claims. */
    private static String manualToken(KeyPair signer, String subject, Object roles) {
        var builder = Jwts.builder()
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS));
        if (subject != null) {
            builder.subject(subject);
        }
        if (roles != null) {
            builder.claim("roles", roles);
        }
        return builder.signWith(signer.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private static String decodeSegment(String token, int index) {
        return new String(Base64.getUrlDecoder().decode(token.split("\\.")[index]), StandardCharsets.UTF_8);
    }

    // ---------- startup ----------

    @Test
    void constructor_missingKeyFile_failsFast() {
        String missing = tmp.resolve("does-not-exist.pem").toString();

        assertThrows(IllegalStateException.class,
                () -> new JwtService(missing, EXPIRATION_MS, ISSUER, AUDIENCE));
    }

    @Test
    void constructor_malformedKeyFile_failsFast() throws IOException {
        Path bad = Files.writeString(tmp.resolve("bad.pem"), "not a pem file");

        assertThrows(IllegalStateException.class,
                () -> new JwtService(bad.toString(), EXPIRATION_MS, ISSUER, AUDIENCE));
    }

    // ---------- generateToken ----------

    @Test
    void generateToken_usesRs256() {
        String token = service.generateToken("alice", List.of("ROLE_USER"));

        assertTrue(decodeSegment(token, 0).contains("\"alg\":\"RS256\""));
    }

    @Test
    void generateToken_containsIssuerAudienceAndSubject() {
        String token = service.generateToken("alice", List.of("ROLE_USER"));
        String payload = decodeSegment(token, 1);

        assertTrue(payload.contains("\"iss\":\"" + ISSUER + "\""));
        assertTrue(payload.contains(AUDIENCE));
        assertTrue(payload.contains("\"sub\":\"alice\""));
    }

    @Test
    void generateToken_verifiesWithDerivedPublicKey() {
        String token = service.generateToken("alice", List.of("ROLE_USER"));

        String subject = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .requireIssuer(ISSUER)
                .requireAudience(AUDIENCE)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();

        assertEquals("alice", subject);
    }

    // ---------- round trip ----------

    @Test
    void roundTrip_returnsUsernameAndRoles() {
        String token = service.generateToken("alice", List.of("ROLE_USER", "ROLE_ADMIN"));

        ClaimsDto claims = service.extractClaims(token);

        assertEquals("alice", claims.username());
        assertEquals(List.of("ROLE_USER", "ROLE_ADMIN"), claims.roles());
    }

    @Test
    void extractClaims_filtersRolesWithoutRolePrefix() {
        String token = service.generateToken("alice", List.of("ROLE_USER", "ADMIN"));

        assertEquals(List.of("ROLE_USER"), service.extractClaims(token).roles());
    }

    @Test
    void extractClaims_missingRolesClaim_returnsEmptyRoles() {
        String token = manualToken(keyPair, "alice", null);

        assertTrue(service.extractClaims(token).roles().isEmpty());
    }

    @Test
    void extractClaims_rolesNotAList_returnsEmptyRoles() {
        String token = manualToken(keyPair, "alice", "ROLE_ADMIN");

        assertTrue(service.extractClaims(token).roles().isEmpty());
    }

    // ---------- rejection cases ----------

    @Test
    void extractClaims_expiredToken_isRejectedAsExpired() throws IOException {
        // Negative lifetime puts exp well past the 30s clock skew
        JwtService expiring = newService(-120_000L, ISSUER, AUDIENCE);
        String token = expiring.generateToken("alice", List.of("ROLE_USER"));

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));

        assertEquals(Reason.EXPIRED, ex.getReason());
    }

    @Test
    void extractClaims_signedByOtherKey_isRejectedAsBadSignature() {
        String token = manualToken(otherKeyPair, "alice", List.of("ROLE_USER"));

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));

        assertEquals(Reason.BAD_SIGNATURE, ex.getReason());
    }

    @Test
    void extractClaims_tamperedPayload_isRejectedAsBadSignature() {
        String original = service.generateToken("alice", List.of("ROLE_USER"));
        String forged = service.generateToken("mallory", List.of("ROLE_ADMIN"));

        // header and signature from one token, payload from another
        String[] a = original.split("\\.");
        String[] b = forged.split("\\.");
        String spliced = a[0] + "." + b[1] + "." + a[2];

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(spliced));

        assertEquals(Reason.BAD_SIGNATURE, ex.getReason());
    }

    @Test
    void extractClaims_wrongIssuer_isRejected() throws IOException {
        JwtService other = newService(EXPIRATION_MS, "someone-else", AUDIENCE);
        String token = other.generateToken("alice", List.of("ROLE_USER"));

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_wrongAudience_isRejected() throws IOException {
        JwtService other = newService(EXPIRATION_MS, ISSUER, "another-api");
        String token = other.generateToken("alice", List.of("ROLE_USER"));

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_algorithmConfusionHs256_isRejected() {
        // Classic attack: sign with HMAC using the public key bytes as the secret
        String token = Jwts.builder()
                .subject("mallory")
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .claim("roles", List.of("ROLE_ADMIN"))
                .signWith(Keys.hmacShaKeyFor(keyPair.getPublic().getEncoded()), Jwts.SIG.HS256)
                .compact();

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_unsignedToken_isRejected() {
        String token = Jwts.builder()
                .subject("mallory")
                .issuer(ISSUER)
                .audience().add(AUDIENCE).and()
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .claim("roles", List.of("ROLE_ADMIN"))
                .compact();

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_missingSubject_isRejectedAsMalformed() {
        String token = manualToken(keyPair, null, List.of("ROLE_USER"));

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));

        assertEquals(Reason.MALFORMED, ex.getReason());
    }

    @Test
    void extractClaims_garbageToken_isRejectedAsMalformed() {
        InvalidTokenException ex = assertThrows(InvalidTokenException.class,
                () -> service.extractClaims("not.a.jwt"));

        assertEquals(Reason.MALFORMED, ex.getReason());
    }

    @Test
    void extractClaims_emptyToken_isRejectedAsEmpty() {
        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(""));

        assertEquals(Reason.EMPTY, ex.getReason());
    }
}