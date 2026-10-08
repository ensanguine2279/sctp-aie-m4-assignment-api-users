package sg.edu.ntu.taskflow_api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

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
        "jwt.secret=" + UsersEndToEndTest.JWT_SECRET,
        "jwt.expiration-ms=3600000"
})
@AutoConfigureMockMvc
class UsersEndToEndTest {

    static final String JWT_SECRET = "end-to-end-test-secret-that-is-at-least-32-bytes";
    private static final long EXPIRATION_MS = 3_600_000L;

    private static final String ADMIN_PASSWORD = "admin-pass-1";
    private static final String ALICE_PASSWORD = "alice-pass-1";
    private static final String BOBBY_PASSWORD = "bobby-pass-1";

    private static final String FORBIDDEN_MESSAGE = "You do not have permission to access this resource";

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
        userRepository.save(new User("admin01", passwordEncoder.encode(ADMIN_PASSWORD), "Admin", UserRole.ADMIN));
        userRepository.save(new User("alice01", passwordEncoder.encode(ALICE_PASSWORD), "Alice", UserRole.USER));
        userRepository.save(new User("bobby01", passwordEncoder.encode(BOBBY_PASSWORD), "Bobby", UserRole.USER));
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
    @DisplayName("a token signed with a different secret is rejected")
    void forgedToken_returns401() throws Exception {
        String forged = new JwtService("a-completely-different-secret-of-32-plus-bytes", EXPIRATION_MS)
                .generateToken("admin01", List.of("ROLE_ADMIN"));

        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token signature is invalid"));
    }

    @Test
    @DisplayName("an expired token is rejected")
    void expiredToken_returns401() throws Exception {
        String expired = new JwtService(JWT_SECRET, -5_000L)
                .generateToken("admin01", List.of("ROLE_ADMIN"));

        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(expired)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token has expired"));
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
                .andExpect(jsonPath("$.claims.username").value("alice01"));
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
        mockMvc.perform(delete("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/users/{id}", bobbyId).header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginBody("bobby01", "new-pass-456")))
                .andExpect(status().isUnauthorized());
    }
}