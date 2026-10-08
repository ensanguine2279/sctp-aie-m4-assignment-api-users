package sg.edu.ntu.taskflow_api.users.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;

/**
 * Called by Spring Security when an unauthenticated request reaches a protected
 * route (no token, or a token JwtAuthFilter rejected).
 *
 * It builds no response itself. It hands the exception to Spring MVC's
 * HandlerExceptionResolver, which runs the matching @ExceptionHandler in
 * GlobalExceptionHandler, so 401 responses share the app's error format.
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver resolver;

    public RestAuthenticationEntryPoint(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
        this.resolver = resolver;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) {

        // Tells the client which scheme to use when it logs in again.
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        // If JwtAuthFilter rejected a token, report why (expired, bad signature, ...).
        // Otherwise fall back to the generic authentication failure.
        Object tokenError = request.getAttribute(JwtAuthFilter.INVALID_TOKEN_ATTRIBUTE);
        Exception cause = tokenError instanceof InvalidTokenException invalidToken ? invalidToken : authException;

        resolver.resolveException(request, response, null, cause);
    }
}