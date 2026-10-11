package sg.edu.ntu.taskflow_api.users.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import sg.edu.ntu.taskflow_api.users.WithRealSecurity;
import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;
import sg.edu.ntu.taskflow_api.users.security.AppUserDetails;
import sg.edu.ntu.taskflow_api.users.security.JwtService;

/**
 * Web-layer tests for AuthController.
 *
 * The REAL SecurityConfig, JwtAuthFilter, @PreAuthorize rule and
 * GlobalExceptionHandler are active. Mocked collaborators:
 * - AuthenticationManager: decides whether credentials are accepted.
 * - JwtService: each test "token" is mapped to claims (or an error), so the
 * real filter builds a real Authentication from it.
 */
@WebMvcTest(AuthController.class)
@WithRealSecurity
class AuthControllerTest {

        private static final String ADMIN = "Bearer admin-token";
        private static final String USER = "Bearer user-token";
        private static final String EXPIRED = "Bearer expired-token";

        private static final String LOGIN_BODY = "{\"username\":\"alice01\",\"password\":\"password1\"}";

        private static final long ALICE_ID = 7L;

        /**
         * What the real DaoAuthenticationProvider returns after a successful login: the
         * principal
         * is the AppUserDetails that DatabaseUserDetailsService loaded, so it carries
         * the database id.
         */
        private static Authentication authenticatedAlice(List<SimpleGrantedAuthority> authorities) {
                return UsernamePasswordAuthenticationToken.authenticated(
                                new AppUserDetails(ALICE_ID, "alice01", "hash", authorities), null, authorities);
        }

        @Autowired
        private MockMvc mockMvc;

        @MockitoBean
        private JwtService jwtService;

        @MockitoBean
        private AuthenticationManager authenticationManager;

        @BeforeEach
        void stubTokens() {
                long expiry = System.currentTimeMillis() + 3_600_000L;
                when(jwtService.extractClaims("admin-token"))
                                .thenReturn(new ClaimsDto("admin01", List.of("ROLE_ADMIN"), expiry, 1L));
                when(jwtService.extractClaims("user-token"))
                                .thenReturn(new ClaimsDto("alice01", List.of("ROLE_USER"), expiry, ALICE_ID));
                when(jwtService.extractClaims("expired-token"))
                                .thenThrow(new InvalidTokenException(Reason.EXPIRED, "Token has expired"));
        }

        private void stubSuccessfulLogin() {
                long expiry = System.currentTimeMillis() + 3_600_000L;
                when(authenticationManager.authenticate(any(Authentication.class)))
                                .thenReturn(authenticatedAlice(List.of(new SimpleGrantedAuthority("ROLE_USER"))));
                when(jwtService.generateToken(eq("alice01"), eq(ALICE_ID), anyList())).thenReturn("jwt-token");
                when(jwtService.extractClaims("jwt-token"))
                                .thenReturn(new ClaimsDto("alice01", List.of("ROLE_USER"), expiry, ALICE_ID));
        }

        // ================= POST /auth/login =================

        @Test
        @DisplayName("login with valid credentials returns 200, a token and the claims")
        void login_validCredentials_returnsTokenAndClaims() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(true))
                                .andExpect(jsonPath("$.token").value("jwt-token"))
                                .andExpect(jsonPath("$.claims.username").value("alice01"))
                                .andExpect(jsonPath("$.claims.roles[0]").value("ROLE_USER"));
        }

        @Test
        @DisplayName("login issues the token with the authenticated user's database id")
        void login_passesTheDatabaseIdToTheToken() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isOk());

                verify(jwtService).generateToken("alice01", ALICE_ID, List.of("ROLE_USER"));
        }

        @Test
        @DisplayName("the login response's claims include the user's id")
        void login_responseIncludesUserId() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.claims.userId").value(ALICE_ID));
        }

        @Test
        @DisplayName("a principal without a database id is a 500, never a token without a uid")
        void login_principalWithoutId_returns500() throws Exception {
                // A plain-String principal: not what DatabaseUserDetailsService produces.
                when(authenticationManager.authenticate(any(Authentication.class)))
                                .thenReturn(UsernamePasswordAuthenticationToken.authenticated(
                                                "alice01", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isInternalServerError())
                                .andExpect(jsonPath("$.message").value("Something went wrong"));

                verify(jwtService, never()).generateToken(any(), anyLong(), anyList());
        }

        @Test
        @DisplayName("login is public: it needs no Authorization header")
        void login_noAuthorizationHeader_isAllowed() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isOk());
        }

        @Test
        @DisplayName("login still works when a stale token is sent in the Authorization header")
        void login_withStaleTokenHeader_stillSucceeds() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login")
                                .header(HttpHeaders.AUTHORIZATION, EXPIRED)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(LOGIN_BODY))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.token").value("jwt-token"));
        }

        @Test
        @DisplayName("login lowercases the username before authenticating and issuing the token")
        void login_uppercaseUsername_isLowercased() throws Exception {
                stubSuccessfulLogin();

                mockMvc.perform(post("/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"username\":\"Alice01\",\"password\":\"password1\"}"))
                                .andExpect(status().isOk());

                ArgumentCaptor<Authentication> captor = ArgumentCaptor.forClass(Authentication.class);
                verify(authenticationManager).authenticate(captor.capture());
                assertThat(captor.getValue().getName()).isEqualTo("alice01");
                verify(jwtService).generateToken(eq("alice01"), eq(ALICE_ID), anyList());
        }

        @Test
        @DisplayName("login only puts ROLE_ authorities into the token")
        void login_filtersNonRoleAuthorities() throws Exception {
                when(authenticationManager.authenticate(any(Authentication.class)))
                                .thenReturn(authenticatedAlice(
                                                List.of(new SimpleGrantedAuthority("ROLE_USER"),
                                                                new SimpleGrantedAuthority("SCOPE_read"),
                                                                new SimpleGrantedAuthority("FACTOR_PASSWORD"))));

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isOk());

                verify(jwtService).generateToken("alice01", ALICE_ID, List.of("ROLE_USER"));
        }

        @Test
        @DisplayName("login with wrong credentials returns 401 with a JSON error body")
        void login_badCredentials_returns401() throws Exception {
                when(authenticationManager.authenticate(any(Authentication.class)))
                                .thenThrow(new BadCredentialsException("Bad credentials"));

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Authentication failed"))
                                .andExpect(jsonPath("$.timestamp").exists());
        }

        @Test
        @DisplayName("a server-side failure during login returns 500, not 401")
        void login_internalFailure_returns500() throws Exception {
                when(authenticationManager.authenticate(any(Authentication.class)))
                                .thenThrow(new InternalAuthenticationServiceException("database is down"));

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(LOGIN_BODY))
                                .andExpect(status().isInternalServerError())
                                .andExpect(jsonPath("$.message").value("Something went wrong"));
        }

        @ParameterizedTest
        @ValueSource(strings = {
                        "{}",
                        "{\"username\":\"alice01\"}",
                        "{\"password\":\"password1\"}",
                        "{\"username\":\"\",\"password\":\"password1\"}",
                        "{\"username\":\"alice01\",\"password\":\"\"}"
        })
        @DisplayName("login with a missing or blank field returns 400 and never reaches authentication")
        void login_invalidBody_returns400(String body) throws Exception {
                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").isNotEmpty());

                verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("login with an oversized username returns 400")
        void login_oversizedUsername_returns400() throws Exception {
                String body = "{\"username\":\"" + "a".repeat(51) + "\",\"password\":\"password1\"}";

                mockMvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.message").value("username: Username is too long"));

                verifyNoInteractions(authenticationManager);
        }

        // ================= POST /auth/validate =================

        @Test
        @DisplayName("validate without a token returns 401")
        void validate_noToken_returns401() throws Exception {
                mockMvc.perform(post("/auth/validate")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"some-token\"}"))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Authentication failed"));
        }

        @Test
        @DisplayName("validate with an expired Authorization token returns 401")
        void validate_expiredAuthorizationToken_returns401() throws Exception {
                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, EXPIRED)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"some-token\"}"))
                                .andExpect(status().isUnauthorized())
                                .andExpect(jsonPath("$.message").value("Token has expired"));
        }

        @Test
        @DisplayName("validate as a plain USER returns 403")
        void validate_asUser_returns403() throws Exception {
                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, USER)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"some-token\"}"))
                                .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("validate as ADMIN returns the claims of a valid token")
        void validate_asAdmin_validToken_returnsClaims() throws Exception {
                when(jwtService.extractClaims("some-token"))
                                .thenReturn(new ClaimsDto("bobby01", List.of("ROLE_MANAGER"),
                                                System.currentTimeMillis() + 60_000L, 8L));

                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"some-token\"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.claims.username").value("bobby01"))
                                .andExpect(jsonPath("$.claims.roles[0]").value("ROLE_MANAGER"))
                                .andExpect(jsonPath("$.valid").value(true))
                                .andExpect(jsonPath("$.error").doesNotExist());
        }

        @Test
        @DisplayName("validate as ADMIN reports EXPIRED for an expired token")
        void validate_asAdmin_expiredToken_reportsReason() throws Exception {
                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"expired-token\"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(false))
                                .andExpect(jsonPath("$.error").value("EXPIRED"))
                                .andExpect(jsonPath("$.claims").doesNotExist());
        }

        @Test
        @DisplayName("validate as ADMIN reports BAD_SIGNATURE for a forged token")
        void validate_asAdmin_forgedToken_reportsReason() throws Exception {
                when(jwtService.extractClaims("forged-token"))
                                .thenThrow(new InvalidTokenException(Reason.BAD_SIGNATURE,
                                                "Token signature is invalid"));

                mockMvc.perform(post("/auth/validate")
                                .header(HttpHeaders.AUTHORIZATION, ADMIN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"token\":\"forged-token\"}"))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.valid").value(false))
                                .andExpect(jsonPath("$.error").value("BAD_SIGNATURE"));
        }
}