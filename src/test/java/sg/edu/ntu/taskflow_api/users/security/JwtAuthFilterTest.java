package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;

import static org.junit.jupiter.api.Assertions.assertThrows;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

/**
 * Direct unit tests for JwtAuthFilter: no Spring context. JwtService is mocked,
 * and Spring's mock servlet classes stand in for the container.
 *
 * Unlike the MockMvc tests, these set the servlet path explicitly, so the
 * shouldNotFilter branch for /auth/login actually runs.
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtService jwtService;

    private JwtAuthFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        filter = new JwtAuthFilter(jwtService);
        request = new MockHttpServletRequest("GET", "/api/users");
        request.setServletPath("/api/users");
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    @AfterEach
    void tearDown() {
        // The SecurityContext is thread-local: never let one test leak into the next.
        SecurityContextHolder.clearContext();
    }

    private ClaimsDto claims(String username, List<String> roles) {
        // The filter does not use the user id, so any valid one will do.
        return new ClaimsDto(username, roles, System.currentTimeMillis() + 3_600_000L, 1L);
    }

    // ---------- shouldNotFilter ----------

    @Test
    @DisplayName("shouldNotFilter is true only for the login route")
    void shouldNotFilter_onlyForLogin() {
        request.setServletPath("/auth/login");
        assertThat(filter.shouldNotFilter(request)).isTrue();

        request.setServletPath("/auth/validate");
        assertThat(filter.shouldNotFilter(request)).isFalse();

        request.setServletPath("/api/users");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    @DisplayName("a request to /auth/login skips token parsing even if it carries a token")
    void loginRoute_isSkipped() throws Exception {
        request.setServletPath("/auth/login");
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer some-token");

        filter.doFilter(request, response, chain);

        verifyNoInteractions(jwtService);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull(); // the chain was still continued
    }

    // ---------- requests with no usable token ----------

    @Test
    @DisplayName("a request with no Authorization header passes through unauthenticated")
    void noHeader_passesThroughAnonymous() throws Exception {
        filter.doFilter(request, response, chain);

        verifyNoInteractions(jwtService);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("a non-Bearer Authorization header is ignored")
    void nonBearerHeader_isIgnored() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNz");

        filter.doFilter(request, response, chain);

        verifyNoInteractions(jwtService);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    // ---------- valid tokens ----------

    @Test
    @DisplayName("a valid token puts the username and roles into the SecurityContext")
    void validToken_setsAuthentication() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer good-token");
        when(jwtService.extractClaims("good-token"))
                .thenReturn(claims("alice01", List.of("ROLE_USER", "ROLE_ADMIN")));

        filter.doFilter(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.isAuthenticated()).isTrue();
        assertThat(auth.getName()).isEqualTo("alice01");
        assertThat(auth.getCredentials()).isNull();
        assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER", "ROLE_ADMIN");
        assertThat(auth.getDetails()).isInstanceOf(WebAuthenticationDetails.class);
        assertThat(request.getAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE)).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("the token is read from after the 'Bearer ' prefix")
    void validToken_isExtractedWithoutPrefix() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer abc.def.ghi");
        when(jwtService.extractClaims("abc.def.ghi")).thenReturn(claims("alice01", List.of("ROLE_USER")));

        filter.doFilter(request, response, chain);

        verify(jwtService).extractClaims("abc.def.ghi");
    }

    @Test
    @DisplayName("a valid token with no roles authenticates the user with no authorities")
    void validToken_noRoles_authenticatesWithoutAuthorities() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer good-token");
        when(jwtService.extractClaims("good-token")).thenReturn(claims("alice01", List.of()));

        filter.doFilter(request, response, chain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getAuthorities()).isEmpty();
    }

    // ---------- invalid tokens ----------

    @Test
    @DisplayName("an invalid token leaves the request anonymous, records the reason and continues the chain")
    void invalidToken_staysAnonymousAndContinues() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer bad-token");
        when(jwtService.extractClaims("bad-token"))
                .thenThrow(new InvalidTokenException(Reason.EXPIRED, "Token has expired"));

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE))
                .isInstanceOfSatisfying(InvalidTokenException.class,
                        ex -> assertThat(ex.getReason()).isEqualTo(Reason.EXPIRED));
        assertThat(chain.getRequest()).isNotNull(); // the filter never answers 401 itself
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    @DisplayName("an invalid token clears any authentication already in the context")
    void invalidToken_clearsExistingAuthentication() throws Exception {
        SecurityContextHolder.getContext()
                .setAuthentication(new TestingAuthenticationToken("someone", "pw", "ROLE_ADMIN"));
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer bad-token");
        when(jwtService.extractClaims("bad-token"))
                .thenThrow(new InvalidTokenException(Reason.BAD_SIGNATURE, "Token signature is invalid"));

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("an empty Bearer token is treated as an invalid token")
    void emptyBearerToken_isTreatedAsInvalid() throws Exception {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer ");
        when(jwtService.extractClaims(""))
                .thenThrow(new InvalidTokenException(Reason.EMPTY, "Token is missing"));

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(request.getAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE))
                .isInstanceOfSatisfying(InvalidTokenException.class,
                        ex -> assertThat(ex.getReason()).isEqualTo(Reason.EMPTY));
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("unexpected errors are not swallowed")
    void unexpectedError_propagates() {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer boom");
        when(jwtService.extractClaims("boom")).thenThrow(new IllegalStateException("unexpected"));

        assertThrows(IllegalStateException.class, () -> filter.doFilter(request, response, chain));

        assertThat(chain.getRequest()).isNull(); // the chain was not continued
    }
}