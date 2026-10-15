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
import java.security.PublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

class JwtServiceTest {

    private static final String ISSUER = "users-service";
    private static final String AUDIENCE = "tasks-api";
    private static final long EXPIRATION_MS = 15 * 60 * 1000L;
    private static final long USER_ID = 7L;

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
        return new JwtService(null, pem.toString(), expirationMs, issuer, audience);
    }

    private static Path writePrivatePem(Path file, KeyPair pair) throws IOException {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(pair.getPrivate().getEncoded());
        return Files.writeString(file,
                "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n");
    }

    private String privatePem() throws IOException {
        return Files.readString(writePrivatePem(tmp.resolve("base64-private.pem"), keyPair));
    }

    private static String pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static JwtService fromKeyValue(String value) {
        return new JwtService(value, null, EXPIRATION_MS, ISSUER, AUDIENCE);
    }

    private static KeyPair newKeyPair(String algorithm, int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm);
        gen.initialize(bits);
        return gen.generateKeyPair();
    }

    private static String oneLineBase64(String text) {
        return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private void assertCanGenerateAndExtractToken(JwtService jwtService) {
        String token = jwtService.generateToken("alice", USER_ID, List.of("ROLE_USER"));

        assertEquals("alice", jwtService.extractClaims(token).username());
    }

    /**
     * Builds a token by hand so tests can omit or alter individual claims. It
     * carries a valid uid.
     */
    private static String manualToken(KeyPair signer, String subject, Object roles) {
        return manualToken(signer, subject, roles, USER_ID);
    }

    /** As above, with an explicit uid claim. A null uid leaves the claim out. */
    private static String manualToken(KeyPair signer, String subject, Object roles, Object uid) {
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
        if (uid != null) {
            builder.claim("uid", uid);
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
                () -> new JwtService(null, missing, EXPIRATION_MS, ISSUER, AUDIENCE));
    }

    @Test
    void constructor_malformedKeyFile_failsFast() throws IOException {
        Path bad = Files.writeString(tmp.resolve("bad.pem"), "not a pem file");

        assertThrows(IllegalStateException.class,
                () -> new JwtService(null, bad.toString(), EXPIRATION_MS, ISSUER, AUDIENCE));
    }

    @Test
    void constructor_base64EncodedPemLoadsKey() throws IOException {
        String encodedPem = Base64.getEncoder()
                .encodeToString(privatePem().getBytes(StandardCharsets.UTF_8));
        JwtService loaded = new JwtService(encodedPem, null, EXPIRATION_MS, ISSUER, AUDIENCE);

        assertCanGenerateAndExtractToken(loaded);
    }

    @Test
    void constructor_rawPemLoadsKey() throws IOException {
        JwtService loaded = new JwtService(privatePem(), null, EXPIRATION_MS, ISSUER, AUDIENCE);

        assertCanGenerateAndExtractToken(loaded);
    }

    @Test
    void constructor_base64KeyTakesPrecedenceOverFilePath() throws IOException {
        String encodedPem = Base64.getEncoder()
                .encodeToString(privatePem().getBytes(StandardCharsets.UTF_8));
        String missingPath = tmp.resolve("does-not-exist.pem").toString();
        JwtService loaded = new JwtService(encodedPem, missingPath, EXPIRATION_MS, ISSUER, AUDIENCE);

        assertCanGenerateAndExtractToken(loaded);
    }

    @Test
    void constructor_blankBase64FallsBackToKeyFile() throws IOException {
        Path pem = writePrivatePem(tmp.resolve("fallback-private.pem"), keyPair);
        JwtService loaded = new JwtService(" \t", pem.toString(), EXPIRATION_MS, ISSUER, AUDIENCE);

        assertCanGenerateAndExtractToken(loaded);
    }

    @Test
    void constructor_missingKeySources_failsFast() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new JwtService(null, " \t", EXPIRATION_MS, ISSUER, AUDIENCE));

        assertTrue(ex.getMessage().contains("Neither 'jwt.private-key-base64' nor 'jwt.private-key-path'"));
    }

    @Test
    void constructor_invalidBase64Key_failsFast() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new JwtService("not-valid-base64", null, EXPIRATION_MS, ISSUER, AUDIENCE));

        assertTrue(ex.getMessage().contains("Failed to load JWT private key from Base64 environment variable"));
    }

    // ---------- the key as an environment variable: the formats people actually
    // paste ----------

    @Test
    void constructor_rawPemWithLeadingWhitespace_loadsKey() throws IOException {
        // a dashboard often leaves a blank line or spaces in front of a pasted value
        assertCanGenerateAndExtractToken(fromKeyValue("\n  " + privatePem()));
    }

    @Test
    void constructor_rawPemWithWindowsLineEndings_loadsKey() throws IOException {
        assertCanGenerateAndExtractToken(fromKeyValue(privatePem().replace("\n", "\r\n")));
    }

    @Test
    void constructor_rawPemOnOneLineWithEscapedNewlines_loadsKey() throws IOException {
        // some platforms store the PEM on a single line with a literal backslash and n
        // instead of line breaks
        assertCanGenerateAndExtractToken(fromKeyValue(privatePem().trim().replace("\n", "\\n")));
    }

    @Test
    void constructor_base64WrappedAcrossLines_loadsKey() throws IOException {
        // what plain `base64 private.pem` prints on Linux: wrapped at 76 columns
        String wrapped = Base64.getMimeEncoder(76, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(privatePem().getBytes(StandardCharsets.UTF_8));
        assertTrue(wrapped.contains("\n"));

        assertCanGenerateAndExtractToken(fromKeyValue(wrapped));
    }

    @Test
    void constructor_base64WithSurroundingWhitespace_loadsKey() throws IOException {
        assertCanGenerateAndExtractToken(fromKeyValue("  " + oneLineBase64(privatePem()) + "\n"));
    }

    @Test
    void constructor_invalidBase64DoesNotFallBackToTheKeyFile() throws IOException {
        // A broken variable must stop the app. It must not quietly start with another
        // key from the path.
        Path validFile = writePrivatePem(tmp.resolve("valid-private.pem"), keyPair);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new JwtService("garbage", validFile.toString(), EXPIRATION_MS, ISSUER, AUDIENCE));

        assertTrue(ex.getMessage().contains("Failed to load JWT private key from Base64 environment variable"));
    }

    @Test
    void constructor_base64KeyIsTheSameKeyAsTheFile() throws IOException {
        JwtService fromBase64 = fromKeyValue(oneLineBase64(privatePem()));

        // each accepts the other's tokens, and both verify with the real public key
        String token = fromBase64.generateToken("alice", USER_ID, List.of("ROLE_USER"));
        assertEquals("alice", service.extractClaims(token).username());
        PublicKey publicKey = keyPair.getPublic();
        assertEquals("alice", Jwts.parser().verifyWith(publicKey).requireIssuer(ISSUER).requireAudience(AUDIENCE)
                .build().parseSignedClaims(token).getPayload().getSubject());
    }

    @Test
    void constructor_pkcs1Key_isRejectedWithAHelpfulMessage() {
        String pkcs1 = pem("RSA PRIVATE KEY", keyPair.getPrivate().getEncoded());

        for (String value : List.of(pkcs1, oneLineBase64(pkcs1))) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> fromKeyValue(value));

            assertTrue(ex.getMessage().contains("PKCS#8"));
            assertTrue(ex.getMessage().contains("RSA PRIVATE KEY"));
            assertTrue(ex.getMessage().contains("openssl pkcs8 -topk8"));
        }
    }

    @Test
    void constructor_publicKeyPastedByMistake_isRejected() {
        String publicPem = pem("PUBLIC KEY", keyPair.getPublic().getEncoded());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> fromKeyValue(publicPem));

        assertTrue(ex.getMessage().contains("PUBLIC KEY"));
    }

    @Test
    void constructor_encryptedKey_isRejected() {
        String encrypted = pem("ENCRYPTED PRIVATE KEY", keyPair.getPrivate().getEncoded());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> fromKeyValue(encrypted));

        assertTrue(ex.getMessage().contains("ENCRYPTED PRIVATE KEY"));
    }

    @Test
    void constructor_nonRsaKey_isRejected() throws Exception {
        KeyPair ec = newKeyPair("EC", 256);

        assertThrows(IllegalArgumentException.class,
                () -> fromKeyValue(pem("PRIVATE KEY", ec.getPrivate().getEncoded())));
    }

    @Test
    void constructor_weakRsaKey_failsAtStartup_notOnTheFirstLogin() throws Exception {
        KeyPair weak = newKeyPair("RSA", 1024);

        // as an environment variable
        IllegalStateException fromVariable = assertThrows(IllegalStateException.class,
                () -> fromKeyValue(pem("PRIVATE KEY", weak.getPrivate().getEncoded())));
        assertTrue(fromVariable.getMessage().contains("at least 2048 bits"));

        // and from a file, which must follow the same rule
        Path weakFile = writePrivatePem(tmp.resolve("weak-private.pem"), weak);
        assertThrows(IllegalStateException.class,
                () -> new JwtService(null, weakFile.toString(), EXPIRATION_MS, ISSUER, AUDIENCE));
    }

    @Test
    void constructor_errorsNeverContainTheKeyMaterial() throws IOException {
        // The failure is logged at startup, so the message and its causes must not echo
        // the secret.
        String body = oneLineBase64(privatePem()).substring(0, 60);
        String pkcs1 = pem("RSA PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String pkcs1Body = pkcs1.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", "").substring(0, 60);

        assertDoesNotLeak(assertThrows(IllegalArgumentException.class, () -> fromKeyValue(body + "!!!")), body);
        assertDoesNotLeak(assertThrows(IllegalArgumentException.class, () -> fromKeyValue(pkcs1)), pkcs1Body);
    }

    private static void assertDoesNotLeak(Throwable failure, String secret) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            assertTrue(t.getMessage() == null || !t.getMessage().contains(secret),
                    "an error message contains the key: " + t.getMessage());
        }
    }

    // ---------- generateToken ----------

    @Test
    void generateToken_usesRs256() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER"));

        assertTrue(decodeSegment(token, 0).contains("\"alg\":\"RS256\""));
    }

    @Test
    void generateToken_containsIssuerAudienceAndSubject() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER"));
        String payload = decodeSegment(token, 1);

        assertTrue(payload.contains("\"iss\":\"" + ISSUER + "\""));
        assertTrue(payload.contains(AUDIENCE));
        assertTrue(payload.contains("\"sub\":\"alice\""));
    }

    @Test
    void generateToken_verifiesWithDerivedPublicKey() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER"));

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

    @Test
    void generateToken_writesTheUidAsAJsonNumber() {
        String payload = decodeSegment(service.generateToken("alice", USER_ID, List.of("ROLE_USER")), 1);

        assertTrue(payload.contains("\"uid\":7"));
        assertTrue(!payload.contains("\"uid\":\"7\""));
    }

    // ---------- round trip ----------

    @Test
    void roundTrip_returnsUsernameAndRoles() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER", "ROLE_ADMIN"));

        ClaimsDto claims = service.extractClaims(token);

        assertEquals("alice", claims.username());
        assertEquals(List.of("ROLE_USER", "ROLE_ADMIN"), claims.roles());
    }

    @Test
    void roundTrip_returnsUserId() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER"));

        assertEquals(USER_ID, service.extractClaims(token).userId());
    }

    @Test
    void roundTrip_userIdBeyondTheIntRange() {
        long big = 5_000_000_000L;
        String token = service.generateToken("alice", big, List.of("ROLE_USER"));

        assertEquals(big, service.extractClaims(token).userId());
    }

    @Test
    void extractClaims_filtersRolesWithoutRolePrefix() {
        String token = service.generateToken("alice", USER_ID, List.of("ROLE_USER", "ADMIN"));

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
        String token = expiring.generateToken("alice", USER_ID, List.of("ROLE_USER"));

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
        String original = service.generateToken("alice", USER_ID, List.of("ROLE_USER"));
        String forged = service.generateToken("mallory", USER_ID, List.of("ROLE_ADMIN"));

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
        String token = other.generateToken("alice", USER_ID, List.of("ROLE_USER"));

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_wrongAudience_isRejected() throws IOException {
        JwtService other = newService(EXPIRATION_MS, ISSUER, "another-api");
        String token = other.generateToken("alice", USER_ID, List.of("ROLE_USER"));

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
                .claim("uid", USER_ID)
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
                .claim("uid", USER_ID)
                .compact();

        assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));
    }

    @Test
    void extractClaims_missingSubject_isRejectedAsMalformed() {
        String token = manualToken(keyPair, null, List.of("ROLE_USER"));

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () -> service.extractClaims(token));

        assertEquals(Reason.MALFORMED, ex.getReason());
    }

    static Stream<Arguments> invalidUids() {
        return Stream.of(
                Arguments.of("missing", null),
                Arguments.of("a string", "7"),
                Arguments.of("a boolean", true),
                Arguments.of("zero", 0),
                Arguments.of("negative", -5),
                Arguments.of("fractional", 1.5));
    }

    @ParameterizedTest(name = "uid {0} is rejected as malformed")
    @MethodSource("invalidUids")
    void extractClaims_invalidUid_isRejectedAsMalformed(String label, Object uid) {
        String token = manualToken(keyPair, "alice", List.of("ROLE_USER"), uid);

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