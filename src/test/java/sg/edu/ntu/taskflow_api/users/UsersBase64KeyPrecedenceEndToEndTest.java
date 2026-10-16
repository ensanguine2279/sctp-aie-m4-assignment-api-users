package sg.edu.ntu.taskflow_api.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Both key sources are set, and they are DIFFERENT keys: the variable holds the
 * signing key and the path points at an unrelated one. The variable must win.
 * This is the real risk when a platform provides the variable but a stale key
 * file or path is still configured.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:e2e-base64-precedence;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop",
})
@AutoConfigureMockMvc
class UsersBase64KeyPrecedenceEndToEndTest {

    private static final String ADMIN_PASSWORD = "admin-pass-1";

    @DynamicPropertySource
    static void jwtProperties(DynamicPropertyRegistry registry) {
        TestJwtKeys.registerWithBase64Key(registry, TestJwtKeys.OTHER_KEY_FILE.toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUpUsers() {
        userRepository.deleteAll();
        userRepository.save(
                new User("admin01", passwordEncoder.encode(ADMIN_PASSWORD), "Admin", UserRole.ADMIN));
    }

    private String login() throws Exception {
        String json = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin01\",\"password\":\"" + ADMIN_PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(json, "$.token");
    }

    @Test
    @DisplayName("the token is signed with the key from the variable, not the key at the path")
    void variableWinsOverThePath() throws Exception {
        String token = login();

        // verifies with the variable's key...
        assertThat(Jwts.parser().verifyWith(TestJwtKeys.SIGNING_KEYS.getPublic()).build()
                .parseSignedClaims(token).getPayload().getSubject()).isEqualTo("admin01");
        // ...and does not verify with the path's key
        assertThatThrownBy(() -> Jwts.parser().verifyWith(TestJwtKeys.OTHER_KEYS.getPublic()).build()
                .parseSignedClaims(token)).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("the service accepts the token it issued")
    void issuedTokenIsAccepted() throws Exception {
        mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, "Bearer " + login()))
                .andExpect(status().isOk());
    }
}