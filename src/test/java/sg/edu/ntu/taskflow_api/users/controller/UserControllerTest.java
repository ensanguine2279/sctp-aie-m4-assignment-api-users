package sg.edu.ntu.taskflow_api.users.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import sg.edu.ntu.taskflow_api.users.config.SecurityConfig;
import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;
import sg.edu.ntu.taskflow_api.users.exception.UserNotFoundException;
import sg.edu.ntu.taskflow_api.users.exception.UsernameAlreadyExistsException;
import sg.edu.ntu.taskflow_api.users.security.JwtService;
import sg.edu.ntu.taskflow_api.users.security.RestAccessDeniedHandler;
import sg.edu.ntu.taskflow_api.users.security.RestAuthenticationEntryPoint;
import sg.edu.ntu.taskflow_api.users.security.UserSecurity;
import sg.edu.ntu.taskflow_api.users.service.UserService;

/**
 * Web-layer tests for UserController.
 *
 * The REAL SecurityConfig, JwtAuthFilter, @PreAuthorize rules and
 * GlobalExceptionHandler are active. Only the collaborators behind them are
 * mocked:
 * - JwtService: each test "token" below is mapped to a set of claims, so the
 * real filter builds a real Authentication from it.
 * - UserService: no database.
 * - UserSecurity: the bean behind @userSecurity in the get-by-id rule.
 *
 * Request bodies are raw JSON strings on purpose: User.password is
 * WRITE_ONLY, so serializing a User with ObjectMapper would drop the password.
 */
@WebMvcTest(UserController.class)
@Import({ SecurityConfig.class, RestAuthenticationEntryPoint.class, RestAccessDeniedHandler.class })
class UserControllerTest {

        private static final String ADMIN = "Bearer admin-token";
        private static final String MANAGER = "Bearer manager-token";
        private static final String USER = "Bearer user-token";
        private static final String EXPIRED = "Bearer expired-token";

        private static final String VALID_BODY = "{\"username\":\"newuser1\",\"password\":\"password1\","
                        + "\"name\":\"New User\",\"role\":\"USER\"}";

        private static final String FORBIDDEN_MESSAGE = "You do not have permission to access this resource";

        @Autowired
        private MockMvc mockMvc;

        @MockitoBean
        private UserService userService;

        @MockitoBean
        private JwtService jwtService;

        @MockitoBean(name = "userSecurity")
        private UserSecurity userSecurity;

        @BeforeEach
        void stubTokens() {
                long expiry = System.currentTimeMillis() + 3_600_000L;
                when(jwtService.extractClaims("admin-token"))
                                .thenReturn(new ClaimsDto("admin01", List.of("ROLE_ADMIN"), expiry));
                when(jwtService.extractClaims("manager-token"))
                                .thenReturn(new ClaimsDto("manager1", List.of("ROLE_MANAGER"), expiry));
                when(jwtService.extractClaims("user-token"))
                                .thenReturn(new ClaimsDto("alice01", List.of("ROLE_USER"), expiry));
                when(jwtService.extractClaims("expired-token"))
                                .thenThrow(new InvalidTokenException(Reason.EXPIRED, "Token has expired"));
        }

        private User user(long id, String username, UserRole role) {
                return User.builder()
                                .id(id)
                                .username(username)
                                .password("$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX")
                                .name("Test User")
                                .role(role)
                                .build();
        }

        // ================= GET /api/users =================

        @Test
        @DisplayName("GET /api/users without a token returns 401")
        void getAllUsers_noToken_returns401() throws Exception {
                mockMvc.perform(get("/api/users"))
                                .andExpect(status().isUnauthorized())
                                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer"))
                                .andExpect(jsonPath("$.message").value("Authentication failed"));

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("GET /api/users with an expired token returns 401")
        void getAllUsers_expiredToken_returns401() throws Exception {
                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, EXPIRED))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Token has expired"));
        }

        @Test
        @DisplayName("GET /api/users as a plain USER returns 403")
        void getAllUsers_asUser_returns403() throws Exception {
                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, USER))
                                .andExpect(status().isForbidden())
                                .andExpect(jsonPath("$.message").value(FORBIDDEN_MESSAGE));

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("GET /api/users as MANAGER returns 200 and never exposes passwords")
        void getAllUsers_asManager_returns200AndHidesPasswords() throws Exception {
                when(userService.getAllUsers())
                                .thenReturn(List.of(user(1L, "alice01", UserRole.USER),
                                                user(2L, "bobby01", UserRole.MANAGER)));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, MANAGER))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.length()").value(2))
                                .andExpect(jsonPath("$[0].username").value("alice01"))
                                .andExpect(jsonPath("$[0].password").doesNotExist())
                                .andExpect(jsonPath("$[1].password").doesNotExist());
        }

        @Test
        @DisplayName("GET /api/users as ADMIN returns 200")
        void getAllUsers_asAdmin_returns200() throws Exception {
                when(userService.getAllUsers()).thenReturn(List.of(user(1L, "alice01", UserRole.USER)));

                mockMvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isOk());
        }

        // ================= GET /api/users/{id} =================

        @Test
        @DisplayName("GET /api/users/{id} without a token returns 401")
        void getUserById_noToken_returns401() throws Exception {
                mockMvc.perform(get("/api/users/1"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("GET /api/users/{id} as the user themselves returns 200")
        void getUserById_ownProfile_returns200() throws Exception {
                when(userSecurity.isSelf(1L, "alice01")).thenReturn(true);
                when(userService.getUserById(1L)).thenReturn(user(1L, "alice01", UserRole.USER));

                mockMvc.perform(get("/api/users/1").header(HttpHeaders.AUTHORIZATION, USER))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.username").value("alice01"));
        }

        @Test
        @DisplayName("GET /api/users/{id} as a USER asking for someone else returns 403")
        void getUserById_otherProfile_returns403() throws Exception {
                // userSecurity.isSelf defaults to false on the mock
                mockMvc.perform(get("/api/users/2").header(HttpHeaders.AUTHORIZATION, USER))
                                .andExpect(status().isForbidden())
                                .andExpect(jsonPath("$.message").value(FORBIDDEN_MESSAGE));

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("GET /api/users/{id} as ADMIN returns 200 and hides the password")
        void getUserById_asAdmin_returns200AndHidesPassword() throws Exception {
                when(userService.getUserById(2L)).thenReturn(user(2L, "bobby01", UserRole.USER));

                mockMvc.perform(get("/api/users/2").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.username").value("bobby01"))
                                .andExpect(jsonPath("$.password").doesNotExist());
        }

        @Test
        @DisplayName("GET /api/users/{id} as MANAGER returns 200")
        void getUserById_asManager_returns200() throws Exception {
                when(userService.getUserById(2L)).thenReturn(user(2L, "bobby01", UserRole.USER));

                mockMvc.perform(get("/api/users/2").header(HttpHeaders.AUTHORIZATION, MANAGER))
                                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("GET /api/users/{id} for a missing user returns 404")
        void getUserById_missing_returns404() throws Exception {
                when(userService.getUserById(99L)).thenThrow(new UserNotFoundException(99L));

                mockMvc.perform(get("/api/users/99").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isNotFound())
                                .andExpect(jsonPath("$.message").isNotEmpty())
                                .andExpect(jsonPath("$.timestamp").exists());
        }

        @Test
        @DisplayName("GET /api/users/{id} with a non-numeric id returns 400")
        void getUserById_nonNumericId_returns400() throws Exception {
                mockMvc.perform(get("/api/users/abc").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").value("Invalid value for 'id'"));
        }

        // ================= POST /api/users =================

        @Test
        @DisplayName("POST /api/users without a token returns 401")
        void createUser_noToken_returns401() throws Exception {
                mockMvc.perform(post("/api/users").contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                                .andExpect(status().isUnauthorized());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("POST /api/users as a plain USER returns 403 and creates nothing")
        void createUser_asUser_returns403() throws Exception {
                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, USER)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isForbidden());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("POST /api/users as MANAGER returns 403")
        void createUser_asManager_returns403() throws Exception {
                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, MANAGER)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isForbidden());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("POST /api/users as ADMIN returns 201 and never echoes the password")
        void createUser_asAdmin_returns201AndHidesPassword() throws Exception {
                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.username").value("newuser1"))
                                .andExpect(jsonPath("$.password").doesNotExist());

                verify(userService).createUser(any(User.class));
        }

        @Test
        @DisplayName("POST /api/users ignores a client-supplied id")
        void createUser_ignoresClientSuppliedId() throws Exception {
                String bodyWithId = "{\"id\":99,\"username\":\"newuser1\",\"password\":\"password1\","
                                + "\"name\":\"New User\",\"role\":\"USER\"}";

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(bodyWithId))
                                .andExpect(status().isCreated());

                ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
                verify(userService).createUser(captor.capture());
                assertThat(captor.getValue().getId()).isZero();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                        // uppercase username
                        "{\"username\":\"NewUser1\",\"password\":\"password1\",\"name\":\"New User\",\"role\":\"USER\"}",
                        // username too short
                        "{\"username\":\"abc\",\"password\":\"password1\",\"name\":\"New User\",\"role\":\"USER\"}",
                        // password too short
                        "{\"username\":\"newuser1\",\"password\":\"short\",\"name\":\"New User\",\"role\":\"USER\"}",
                        // blank name
                        "{\"username\":\"newuser1\",\"password\":\"password1\",\"name\":\"\",\"role\":\"USER\"}",
                        // role missing
                        "{\"username\":\"newuser1\",\"password\":\"password1\",\"name\":\"New User\"}",
                        // role not in the enum
                        "{\"username\":\"newuser1\",\"password\":\"password1\",\"name\":\"New User\",\"role\":\"SUPERADMIN\"}",
                        // empty object
                        "{}"
        })
        @DisplayName("POST /api/users with an invalid body returns 400 and creates nothing")
        void createUser_invalidBody_returns400(String body) throws Exception {
                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").isNotEmpty());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("POST /api/users with an uppercase username reports the field and the rule")
        void createUser_uppercaseUsername_reportsFieldError() throws Exception {
                String body = "{\"username\":\"NewUser1\",\"password\":\"password1\","
                                + "\"name\":\"New User\",\"role\":\"USER\"}";

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message")
                                                .value("username: Username may only contain lowercase letters and digits"));
        }

        @Test
        @DisplayName("POST /api/users with malformed JSON returns 400")
        void createUser_malformedJson_returns400() throws Exception {
                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{ this is not json"))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").value("Malformed request body"));

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("POST /api/users with a taken username returns 409")
        void createUser_duplicateUsername_returns409() throws Exception {
                doThrow(new UsernameAlreadyExistsException("newuser1")).when(userService).createUser(any(User.class));

                mockMvc.perform(post("/api/users")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isConflict())
                                .andExpect(jsonPath("$.message").isNotEmpty());
        }

        // ================= PUT /api/users/{id} =================

        @Test
        @DisplayName("PUT /api/users/{id} without a token returns 401")
        void updateUser_noToken_returns401() throws Exception {
                mockMvc.perform(put("/api/users/1").contentType(MediaType.APPLICATION_JSON).content(VALID_BODY))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("PUT /api/users/{id} as a plain USER returns 403 (no privilege escalation)")
        void updateUser_asUser_returns403() throws Exception {
                String escalation = "{\"username\":\"alice01\",\"password\":\"password1\","
                                + "\"name\":\"Alice\",\"role\":\"ADMIN\"}";

                mockMvc.perform(put("/api/users/1")
                                .header(HttpHeaders.AUTHORIZATION, USER)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(escalation))
                                .andExpect(status().isForbidden());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("PUT /api/users/{id} as ADMIN returns 200 and hides the password")
        void updateUser_asAdmin_returns200() throws Exception {
                when(userService.updateUser(eq(1L), any(User.class))).thenReturn(user(1L, "newuser1", UserRole.USER));

                mockMvc.perform(put("/api/users/1")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.username").value("newuser1"))
                                .andExpect(jsonPath("$.password").doesNotExist());
        }

        @Test
        @DisplayName("PUT /api/users/{id} for a missing user returns 404")
        void updateUser_missing_returns404() throws Exception {
                when(userService.updateUser(eq(99L), any(User.class))).thenThrow(new UserNotFoundException(99L));

                mockMvc.perform(put("/api/users/99")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isNotFound());
        }

        @ParameterizedTest
        @ValueSource(strings = {
                        "{\"username\":\"NewUser1\",\"password\":\"password1\",\"name\":\"New User\",\"role\":\"USER\"}",
                        "{\"username\":\"newuser1\",\"password\":\"short\",\"name\":\"New User\",\"role\":\"USER\"}",
                        "{}"
        })
        @DisplayName("PUT /api/users/{id} with an invalid body returns 400 and updates nothing")
        void updateUser_invalidBody_returns400(String body) throws Exception {
                mockMvc.perform(put("/api/users/1")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").isNotEmpty());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("PUT /api/users/{id} with a username owned by someone else returns 409")
        void updateUser_duplicateUsername_returns409() throws Exception {
                when(userService.updateUser(eq(1L), any(User.class)))
                                .thenThrow(new UsernameAlreadyExistsException("newuser1"));

                mockMvc.perform(put("/api/users/1")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(VALID_BODY))
                                .andExpect(status().isConflict())
                                .andExpect(jsonPath("$.message").isNotEmpty());
        }

        // ================= DELETE /api/users/{id} =================

        @Test
        @DisplayName("DELETE /api/users/{id} without a token returns 401")
        void deleteUser_noToken_returns401() throws Exception {
                mockMvc.perform(delete("/api/users/1"))
                                .andExpect(status().isUnauthorized());
        }

        @Test
        @DisplayName("DELETE /api/users/{id} as a plain USER returns 403 and deletes nothing")
        void deleteUser_asUser_returns403() throws Exception {
                mockMvc.perform(delete("/api/users/1").header(HttpHeaders.AUTHORIZATION, USER))
                                .andExpect(status().isForbidden());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("DELETE /api/users/{id} as MANAGER returns 403")
        void deleteUser_asManager_returns403() throws Exception {
                mockMvc.perform(delete("/api/users/1").header(HttpHeaders.AUTHORIZATION, MANAGER))
                                .andExpect(status().isForbidden());

                verifyNoInteractions(userService);
        }

        @Test
        @DisplayName("DELETE /api/users/{id} as ADMIN returns 204")
        void deleteUser_asAdmin_returns204() throws Exception {
                mockMvc.perform(delete("/api/users/1").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isNoContent());

                verify(userService).deleteUser(1L);
        }

        @Test
        @DisplayName("DELETE /api/users/{id} for a missing user returns 404")
        void deleteUser_missing_returns404() throws Exception {
                doThrow(new UserNotFoundException(99L)).when(userService).deleteUser(99L);

                mockMvc.perform(delete("/api/users/99").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isNotFound());
        }

        // ================= generic error handling =================

        @Test
        @DisplayName("an unknown path returns 404, not 500")
        void unknownPath_asAdmin_returns404() throws Exception {
                mockMvc.perform(get("/api/nothing-here").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isNotFound())
                                .andExpect(jsonPath("$.message").value("Not Found"));
        }

        @Test
        @DisplayName("an unsupported HTTP method returns 405, not 500")
        void unsupportedMethod_asAdmin_returns405() throws Exception {
                mockMvc.perform(patch("/api/users/1").header(HttpHeaders.AUTHORIZATION, ADMIN))
                                .andExpect(status().isMethodNotAllowed())
                                .andExpect(jsonPath("$.message").value("Method Not Allowed"));
        }
}