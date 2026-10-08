package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.HandlerExceptionResolver;

import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

/**
 * The entry point is only a bridge: these tests check WHICH exception it hands
 * to the resolver. What the response looks like is GlobalExceptionHandler's job
 * (covered by the MVC tests).
 */
@ExtendWith(MockitoExtension.class)
class RestAuthenticationEntryPointTest {

    @Mock
    private HandlerExceptionResolver resolver;

    @InjectMocks
    private RestAuthenticationEntryPoint entryPoint;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest("GET", "/api/users");
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("with no token problem, the Spring Security exception is passed to the resolver")
    void commence_noTokenError_passesAuthenticationException() {
        AuthenticationException authException = new InsufficientAuthenticationException("Full authentication is required");

        entryPoint.commence(request, response, authException);

        verify(resolver).resolveException(request, response, null, authException);
    }

    @Test
    @DisplayName("when the filter rejected a token, that exception is passed instead")
    void commence_tokenRejectedByFilter_passesInvalidTokenException() {
        InvalidTokenException tokenError = new InvalidTokenException(Reason.EXPIRED, "Token has expired");
        request.setAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE, tokenError);
        AuthenticationException authException = new InsufficientAuthenticationException("Full authentication is required");

        entryPoint.commence(request, response, authException);

        verify(resolver).resolveException(request, response, null, tokenError);
    }

    @Test
    @DisplayName("an attribute of the wrong type is ignored")
    void commence_unexpectedAttributeType_fallsBackToAuthenticationException() {
        request.setAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE, "not an exception");
        AuthenticationException authException = new InsufficientAuthenticationException("Full authentication is required");

        entryPoint.commence(request, response, authException);

        verify(resolver).resolveException(request, response, null, authException);
    }

    @Test
    @DisplayName("the response advertises the Bearer scheme")
    void commence_setsWwwAuthenticateHeader() {
        entryPoint.commence(request, response, new InsufficientAuthenticationException("Full authentication is required"));

        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
    }
}
