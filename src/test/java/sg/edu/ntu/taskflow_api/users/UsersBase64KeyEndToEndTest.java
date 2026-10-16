package sg.edu.ntu.taskflow_api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;
import sg.edu.ntu.taskflow_api.users.security.JwtService;

/**
 * The whole application, nothing mocked, started with the private key supplied
 * ONLY as jwt.private-key-base64 (the Railway case): there is no key file, and
 * jwt.private-key-path is empty.
 *
 * It follows the same pattern as UsersEndToEndTest, which covers the file-based
 * setup.
 */
@SpringBootTest(properties = {
                "spring.datasource.url=jdbc:h2:mem:e2e-base64;DB_CLOSE_DELAY=-1",
                "spring.jpa.hibernate.ddl-auto=create-drop",
})
@AutoConfigureMockMvc
class UsersBase64KeyEndToEndTest {

        private static final long EXPIRATION_MS = 3_600_000L;
        private static final String ADMIN_PASSWORD = "admin-pass-1";
        private static final String ALICE_PASSWORD = "alice-pass-1";

        @DynamicPropertySource
        static void jwtProperties(DynamicPropertyRegistry registry) {
                TestJwtKeys.registerWithBase64Key(registry, ""); // no key file at all
        }

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Autowired
        private Environment environment;

        @BeforeEach
        void setUpUsers() {
                userRepository.deleteAll();
                userRepository.save(
                                new User("admin01", passwordEncoder.encode(ADMIN_PASSWORD), "Admin", UserRole.ADMIN));
                userRepository.save(
                                new User("alice01", passwordEncoder.encode(ALICE_PASSWORD), "Alice", UserRole.USER));
        }

        // ---------- helpers ----------

        private String loginAndGetToken(String username, String password) throws Exception {
                String json = mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
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

        private static Jws<Claims> verifyWithTheSigningKey(String token) {
                return Jwts.parser()
                                .verifyWith(TestJwtKeys.SIGNING_KEYS.getPublic())
                                .requireIssuer(TestJwtKeys.ISSUER)
                                .requireAudience(TestJwtKeys.AUDIENCE)
                                .build()
                                .parseSignedClaims(token);
        }

        // ---------- the key really comes from the variable ----------

        @Test
        @DisplayName("the application is configured with the key variable and no key file")
        void configuration_hasTheVariableAndNoPath() {
                assertThat(environment.getProperty("jwt.private-key-base64")).isNotBlank();
                assertThat(environment.getProperty("jwt.private-key-path")).isEmpty();
        }

        // ---------- the full flow ----------

        @Test
        @DisplayName("login returns an RS256 token signed with the key from the variable, carrying the user's id")
        void login_tokenIsSignedWithTheKeyFromTheVariable() throws Exception {
                String token = loginAndGetToken("admin01", ADMIN_PASSWORD);

                Jws<Claims> verified = verifyWithTheSigningKey(token); // fails unless the signature matches
                assertThat(verified.getHeader().getAlgorithm()).isEqualTo("RS256");
                assertThat(verified.getPayload().getSubject()).isEqualTo("admin01");

                String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                                StandardCharsets.UTF_8);
                Object uid = JsonPath.read(payload, "$.uid");
                assertThat(uid).isInstanceOf(Number.class);
                assertThat(((Number) uid).longValue()).isEqualTo(idOf("admin01"));
                assertThat(payload).contains("\"roles\":[\"ROLE_ADMIN\"]");
        }

        @Test
        @DisplayName("a token issued in this mode is accepted by the service, and the role rules still apply")
        void issuedToken_worksOnProtectedEndpoints() throws Exception {
                String adminToken = loginAndGetToken("admin01", ADMIN_PASSWORD);
                String aliceToken = loginAndGetToken("alice01", ALICE_PASSWORD);

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(aliceToken)))
                                .andExpect(status().isForbidden());
                // the id-based self check, using the uid from the token
                mockMvc.perform(get("/api/users/{id}", idOf("alice01")).header(HttpHeaders.AUTHORIZATION,
                                bearer(aliceToken)))
                                .andExpect(status().isOk());
                mockMvc.perform(get("/api/users/{id}", idOf("admin01")).header(HttpHeaders.AUTHORIZATION,
                                bearer(aliceToken)))
                                .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("a token from a file-based service with the same key is accepted: both setups use the same key")
        void tokenFromTheFileBasedSetup_isAccepted() throws Exception {
                JwtService fileBased = new JwtService(null, TestJwtKeys.SIGNING_KEY_FILE.toString(), EXPIRATION_MS,
                                TestJwtKeys.ISSUER, TestJwtKeys.AUDIENCE);
                String token = fileBased.generateToken("admin01", idOf("admin01"), List.of("ROLE_ADMIN"));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(token)))
                                .andExpect(status().isOk());
        }

        // ---------- rejections still hold in this mode ----------

        @Test
        @DisplayName("a token signed by a different key is rejected")
        void tokenSignedByAnotherKey_returns401() throws Exception {
                String forged = Jwts.builder()
                                .subject("admin01").issuer(TestJwtKeys.ISSUER)
                                .audience().add(TestJwtKeys.AUDIENCE).and()
                                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                                .claim("roles", List.of("ROLE_ADMIN"))
                                .claim("uid", idOf("admin01"))
                                .signWith(TestJwtKeys.OTHER_KEYS.getPrivate(), Jwts.SIG.RS256)
                                .compact();

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(forged)))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Token signature is invalid"));
        }

        @Test
        @DisplayName("a token with a tampered signature is rejected")
        void tamperedSignature_returns401() throws Exception {
                String token = loginAndGetToken("admin01", ADMIN_PASSWORD);
                int index = token.lastIndexOf('.') + 10;
                char replacement = token.charAt(index) == 'A' ? 'B' : 'A';
                String tampered = token.substring(0, index) + replacement + token.substring(index + 1);

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(tampered)))
                                .andExpect(status().isUnauthorized());
        }
}