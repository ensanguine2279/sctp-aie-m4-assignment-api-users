package sg.edu.ntu.taskflow_api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;
import sg.edu.ntu.taskflow_api.users.security.JwtService;

/**
 * End-to-end tests: the whole application starts, and NOTHING is mocked.
 * Requests go through the real security filter chain, JWT filter, controllers,
 * services, BCrypt and an in-memory H2 database.
 *
 * Users are created directly in the database before each test, with real
 * BCrypt hashes, so the tests do not depend on DataLoader or AdminSeeder.
 * The database has its own name so it cannot clash with other Spring contexts
 * in the same test run.
 */
@SpringBootTest(properties = {
                "spring.datasource.url=jdbc:h2:mem:e2e;DB_CLOSE_DELAY=-1",
                "spring.jpa.hibernate.ddl-auto=create-drop",
})
@AutoConfigureMockMvc
class UsersEndToEndTest {

        // Package-private (not private) because the annotation above refers to them.
        static final String ISSUER = TestJwtKeys.ISSUER;
        static final String AUDIENCE = TestJwtKeys.AUDIENCE;
        private static final long EXPIRATION_MS = 3_600_000L;
        // generateToken needs a user id. For tokens that are rejected for another
        // reason, any valid id will do.
        private static final long ANY_UID = 1L;

        // Throwaway RSA keys generated per test run, so no real key file is needed.
        private static final Path SIGNING_KEY_FILE = TestJwtKeys.SIGNING_KEY_FILE;
        private static final Path OTHER_KEY_FILE = TestJwtKeys.OTHER_KEY_FILE;

        private static final String ADMIN_PASSWORD = "admin-pass-1";
        private static final String ALICE_PASSWORD = "alice-pass-1";
        private static final String BOBBY_PASSWORD = "bobby-pass-1";

        private static final String FORBIDDEN_MESSAGE = "You do not have permission to access this resource";

        @DynamicPropertySource
        static void jwtProperties(DynamicPropertyRegistry registry) {
                TestJwtKeys.register(registry);
        }

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @BeforeEach
        void setUpUsers() {
                // Each test starts from the same three users, whatever ran before it.
                userRepository.deleteAll();
                userRepository.save(
                                new User("admin01", passwordEncoder.encode(ADMIN_PASSWORD), "Admin", UserRole.ADMIN));
                userRepository.save(
                                new User("alice01", passwordEncoder.encode(ALICE_PASSWORD), "Alice", UserRole.USER));
                userRepository.save(
                                new User("bobby01", passwordEncoder.encode(BOBBY_PASSWORD), "Bobby", UserRole.USER));
        }

        // ---------- helpers ----------

        private static String loginBody(String username, String password) {
                return "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        }

        private String loginAndGetToken(String username, String password) throws Exception {
                String json = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody(username, password)))
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString();
                return JsonPath.read(json, "$.token");
        }

        private static String bearer(String token) {
                return "Bearer " + token;
        }

        private long idOf(String username) {
                return userRepository.findByUsername(username).orElseThrow().getId();
        }

        /**
         * The decoded JSON payload of a JWT, to check what is really inside the token.
         */
        private static String payloadOf(String token) {
                return new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
        }

        /**
         * A correctly signed token with the right issuer and audience, and the given
         * "uid" claim (null omits it).
         */
        private static String tokenWithUid(Object uid) {
                return Jwts.builder()
                                .subject("admin01").issuer(ISSUER)
                                .audience().add(AUDIENCE).and()
                                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                                .claim("roles", List.of("ROLE_ADMIN"))
                                .claim("uid", uid)
                                .signWith(TestJwtKeys.SIGNING_KEYS.getPrivate(), Jwts.SIG.RS256)
                                .compact();
        }

        // ================= login =================

        @Test
        @DisplayName("login returns a token with the user's claims and no internal authorities")
        void login_returnsTokenAndClaims() throws Exception {
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("admin01", ADMIN_PASSWORD)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(true))
                                .andExpect(jsonPath("$.token").isNotEmpty())
                                .andExpect(jsonPath("$.claims.username").value("admin01"))
                                .andExpect(jsonPath("$.claims.roles[0]").value("ROLE_ADMIN"))
                                // Spring Security 7 adds FACTOR_PASSWORD at login; it must not reach the token.
                                .andExpect(jsonPath("$.claims.roles.length()").value(1));
        }

        @Test
        @DisplayName("the token's expiry follows jwt.expiration-ms")
        void login_expiryFollowsConfiguration() throws Exception {
                long before = System.currentTimeMillis();
                String json = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("admin01", ADMIN_PASSWORD)))
                                .andExpect(status().isOk())
                                .andReturn().getResponse().getContentAsString();
                long after = System.currentTimeMillis();

                long expiration = ((Number) JsonPath.read(json, "$.claims.expiration")).longValue();

                // JWT keeps whole seconds, so the value can be up to 1000 ms below the exact
                // expiry.
                assertThat(expiration).isBetween(before + EXPIRATION_MS - 1000, after + EXPIRATION_MS);
        }

        @Test
        @DisplayName("the username is case-insensitive at login")
        void login_usernameIsCaseInsensitive() throws Exception {
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("Admin01", ADMIN_PASSWORD)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.claims.username").value("admin01"));
        }

        @Test
        @DisplayName("a wrong password and an unknown user get the same generic 401")
        void login_failures_areIndistinguishable() throws Exception {
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("admin01", "wrong-password")))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Authentication failed"));

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("nobody01", ADMIN_PASSWORD)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Authentication failed"));
        }

        @Test
        @DisplayName("the token carries the user's database id as a numeric uid claim")
        void login_tokenCarriesUid() throws Exception {
                long adminId = idOf("admin01");
                String json = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("admin01", ADMIN_PASSWORD)))
                                .andExpect(status().isOk())
                                // the response's claims show it too
                                .andExpect(jsonPath("$.claims.userId").value(adminId))
                                .andReturn().getResponse().getContentAsString();

                // what is really inside the signed token: a JSON number, not a string
                String payload = payloadOf(JsonPath.read(json, "$.token"));
                Object uid = JsonPath.read(payload, "$.uid");
                assertThat(uid).isInstanceOf(Number.class);
                assertThat(((Number) uid).longValue()).isEqualTo(adminId);
        }

        @Test
        @DisplayName("each user's token carries their own id")
        void login_eachUserGetsTheirOwnUid() throws Exception {
                String aliceToken = loginAndGetToken("alice01", ALICE_PASSWORD);
                String bobbyToken = loginAndGetToken("bobby01", BOBBY_PASSWORD);

                long aliceUid = ((Number) JsonPath.read(payloadOf(aliceToken), "$.uid")).longValue();
                long bobbyUid = ((Number) JsonPath.read(payloadOf(bobbyToken), "$.uid")).longValue();

                assertThat(aliceUid).isEqualTo(idOf("alice01"));
                assertThat(bobbyUid).isEqualTo(idOf("bobby01"));
                assertThat(aliceUid).isNotEqualTo(bobbyUid);
        }

        // ================= using the token =================

        @Test
        @DisplayName("log in as admin, then use the token to list users (no passwords in the response)")
        void adminToken_listsUsers() throws Exception {
                String token = loginAndGetToken("admin01", ADMIN_PASSWORD);

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.length()").value(3))
                                .andExpect(jsonPath("$[*].password").isEmpty());
        }

        @Test
        @DisplayName("a protected endpoint without a token returns a JSON 401")
        void noToken_returns401() throws Exception {
                mockMvc.perform(get("/api/users"))
                                .andExpect(status().isUnauthorized())
                                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                                .andExpect(jsonPath("$.message").value("Authentication failed"));
        }

        @Test
        @DisplayName("a token signed with a different private key is rejected")
        void forgedToken_returns401() throws Exception {
                String forged = new JwtService(OTHER_KEY_FILE.toString(), EXPIRATION_MS, ISSUER, AUDIENCE)
                                .generateToken("admin01", ANY_UID, List.of("ROLE_ADMIN"));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Token signature is invalid"));
        }

        @Test
        @DisplayName("an expired token is rejected")
        void expiredToken_returns401() throws Exception {
                // The parser allows 30s of clock skew, so the token must expire well beyond
                // that.
                String expired = new JwtService(SIGNING_KEY_FILE.toString(), -120_000L, ISSUER, AUDIENCE)
                                .generateToken("admin01", ANY_UID, List.of("ROLE_ADMIN"));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(expired)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Token has expired"));
        }

        @Test
        @DisplayName("a correctly signed token with the wrong issuer or audience is rejected")
        void wrongIssuerOrAudience_returns401() throws Exception {
                String wrongIssuer = new JwtService(SIGNING_KEY_FILE.toString(), EXPIRATION_MS, "someone-else",
                                AUDIENCE)
                                .generateToken("admin01", ANY_UID, List.of("ROLE_ADMIN"));
                String wrongAudience = new JwtService(SIGNING_KEY_FILE.toString(), EXPIRATION_MS, ISSUER, "another-api")
                                .generateToken("admin01", ANY_UID, List.of("ROLE_ADMIN"));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(wrongIssuer)))
                                .andExpect(status().isUnauthorized());

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(wrongAudience)))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("a correctly signed token without a valid uid claim is rejected")
        void tokenWithoutValidUid_returns401() throws Exception {
                // Control: the helper's token is accepted when the uid is fine, so the 401s
                // below are about the uid.
                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(tokenWithUid(1L))))
                                .andExpect(status().isOk());

                // null omits the claim. The rest are present but invalid.
                for (Object uid : Arrays.asList(null, "1", true, 0, -1, 1.5)) {
                        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(tokenWithUid(uid))))
                                        .andExpect(status().isUnauthorized())
                                        .andExpect(jsonPath("$.message").value("Token has no valid uid"));
                }
        }

        @Test
        @DisplayName("a non-Bearer Authorization header is treated as unauthenticated")
        void nonBearerAuthorizationHeader_returns401() throws Exception {
                for (String header : List.of("Basic YWRtaW46cGFzcw==", "Token abc", "Bearer")) {
                        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, header))
                                        .andExpect(status().isUnauthorized())
                                        .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
                }
        }

        @Test
        @DisplayName("a Bearer header carrying garbage is rejected")
        void garbageBearerToken_returns401() throws Exception {
                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer("not.a.jwt")))
                                .andExpect(status().isUnauthorized())
                                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"));
        }

        @Test
        @DisplayName("HS256 (algorithm confusion) and unsigned tokens are rejected over HTTP")
        void hs256AndUnsignedTokens_return401() throws Exception {
                Date exp = new Date(System.currentTimeMillis() + EXPIRATION_MS);

                String hs256 = Jwts.builder()
                                .subject("admin01").issuer(ISSUER)
                                .audience().add(AUDIENCE).and()
                                .expiration(exp)
                                .claim("roles", List.of("ROLE_ADMIN"))
                                .claim("uid", ANY_UID)
                                .signWith(Keys.hmacShaKeyFor(TestJwtKeys.SIGNING_KEYS.getPublic().getEncoded()),
                                                Jwts.SIG.HS256)
                                .compact();

                String unsigned = Jwts.builder()
                                .subject("admin01").issuer(ISSUER)
                                .audience().add(AUDIENCE).and()
                                .expiration(exp)
                                .claim("roles", List.of("ROLE_ADMIN"))
                                .claim("uid", ANY_UID)
                                .compact();

                for (String token : List.of(hs256, unsigned)) {
                        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                        .andExpect(status().isUnauthorized());
                }
        }

        @Test
        @DisplayName("the Bearer scheme is case-insensitive")
        void lowercaseBearerScheme_isAccepted() throws Exception {
                String token = loginAndGetToken("admin01", ADMIN_PASSWORD);

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, "bearer " + token))
                                .andExpect(status().isOk());
        }

        // ================= roles =================

        @Test
        @DisplayName("a plain USER can read their own profile but nothing else")
        void userRole_isLimitedToOwnProfile() throws Exception {
                long aliceId = idOf("alice01");
                long bobbyId = idOf("bobby01");
                String token = loginAndGetToken("alice01", ALICE_PASSWORD);

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isForbidden())
                                .andExpect(jsonPath("$.message").value(FORBIDDEN_MESSAGE));

                // The real UserSecurity bean and the real SpEL rule decide these two.
                mockMvc.perform(get("/api/users/{id}", aliceId).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.username").value("alice01"));

                mockMvc.perform(get("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isForbidden());

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"newuser1\",\"password\":\"new-pass-123\","
                                                + "\"name\":\"New User\",\"role\":\"ADMIN\"}"))
                                .andExpect(status().isForbidden());

                mockMvc.perform(delete("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isForbidden());

                assertThat(userRepository.existsById(bobbyId)).isTrue(); // the forbidden calls changed nothing
                assertThat(userRepository.findByUsername("newuser1")).isEmpty();
        }

        @Test
        @DisplayName("only an admin can inspect a token through /auth/validate")
        void validateEndpoint_isAdminOnly() throws Exception {
                String aliceToken = loginAndGetToken("alice01", ALICE_PASSWORD);
                String adminToken = loginAndGetToken("admin01", ADMIN_PASSWORD);
                String body = "{\"token\":\"" + aliceToken + "\"}";

                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, bearer(aliceToken))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isForbidden());

                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(true))
                                .andExpect(jsonPath("$.claims.username").value("alice01"))
                                .andExpect(jsonPath("$.claims.userId").value(idOf("alice01")));
        }

        // ================= admin workflows =================

        @Test
        @DisplayName("an admin creates a user, who can then log in with the password they were given")
        void adminCreatesUser_whoCanLogIn() throws Exception {
                String adminToken = loginAndGetToken("admin01", ADMIN_PASSWORD);
                String body = "{\"username\":\"newuser1\",\"password\":\"new-pass-123\","
                                + "\"name\":\"New User\",\"role\":\"USER\"}";

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.username").value("newuser1"))
                                .andExpect(jsonPath("$.password").doesNotExist());

                // Stored as a BCrypt hash, never as the raw password.
                User saved = userRepository.findByUsername("newuser1").orElseThrow();
                assertThat(saved.getPassword()).startsWith("$2").isNotEqualTo("new-pass-123");

                // The hash written at creation is the one login checks against.
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("newuser1", "new-pass-123")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.claims.roles[0]").value("ROLE_USER"));
        }

        @Test
        @DisplayName("creating a user with a taken username returns 409")
        void createDuplicateUsername_returns409() throws Exception {
                String adminToken = loginAndGetToken("admin01", ADMIN_PASSWORD);
                String body = "{\"username\":\"alice01\",\"password\":\"new-pass-123\","
                                + "\"name\":\"Another Alice\",\"role\":\"USER\"}";

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isConflict())
                                .andExpect(jsonPath("$.message").isNotEmpty());

                assertThat(userRepository.count()).isEqualTo(3); // still only the three original users
        }

        @Test
        @DisplayName("an admin updates a user (new password and role take effect), then deletes them")
        void adminUpdatesThenDeletesUser() throws Exception {
                String adminToken = loginAndGetToken("admin01", ADMIN_PASSWORD);
                long bobbyId = idOf("bobby01");

                // update
                mockMvc.perform(put("/api/users/{id}", bobbyId)
                                .header(HttpHeaders.AUTHORIZATION, bearer(adminToken))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"bobby01\",\"password\":\"new-pass-456\","
                                                + "\"name\":\"Bobby Updated\",\"role\":\"MANAGER\"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.name").value("Bobby Updated"))
                                .andExpect(jsonPath("$.role").value("MANAGER"))
                                .andExpect(jsonPath("$.password").doesNotExist());

                // the new password and role work; the old password does not
                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("bobby01", "new-pass-456")))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.claims.roles[0]").value("ROLE_MANAGER"));

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("bobby01", BOBBY_PASSWORD)))
                                .andExpect(status().isUnauthorized());

                // delete
                mockMvc.perform(delete("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION,
                                bearer(adminToken)))
                                .andExpect(status().isNoContent());

                mockMvc.perform(get("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                                .andExpect(status().isNotFound());

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(loginBody("bobby01", "new-pass-456")))
                                .andExpect(status().isUnauthorized());
        }
}