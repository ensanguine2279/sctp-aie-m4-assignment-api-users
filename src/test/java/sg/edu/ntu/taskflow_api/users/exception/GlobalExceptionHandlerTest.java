package sg.edu.ntu.taskflow_api.users.exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

/**
 * Tests GlobalExceptionHandler on its own, with no Spring context or security.
 *
 * A throwaway controller throws one exception per endpoint, and a standalone
 * MockMvc routes each through the real handler. This checks three things:
 * - the right status and message for each exception,
 * - that internal details (SQL, constraint names, passwords) never reach the
 * client,
 * - that the most specific handler wins over its more general parent.
 */
class GlobalExceptionHandlerTest {

    private static final UserNotFoundException USER_NOT_FOUND = new UserNotFoundException(5L);
    private static final UsernameAlreadyExistsException DUPLICATE_USERNAME = new UsernameAlreadyExistsException(
            "alice01");

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new ThrowingController())
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    private String bodyOf(ResultActions result) throws Exception {
        return result.andReturn().getResponse().getContentAsString();
    }

    // ---------- application exceptions ----------

    @Test
    @DisplayName("UserNotFoundException returns 404 with the exception's own message")
    void userNotFound_returns404() throws Exception {
        mockMvc.perform(get("/test/not-found"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(USER_NOT_FOUND.getMessage()))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("UsernameAlreadyExistsException returns 409 with the exception's own message")
    void duplicateUsername_returns409() throws Exception {
        mockMvc.perform(get("/test/duplicate-username"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(DUPLICATE_USERNAME.getMessage()));
    }

    @Test
    @DisplayName("InvalidTokenException returns 401 with the reason as the message")
    void invalidToken_returns401() throws Exception {
        mockMvc.perform(get("/test/invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Token has expired"));
    }

    // ---------- database and validation exceptions ----------

    @Test
    @DisplayName("DataIntegrityViolationException returns 409 and hides the SQL detail")
    void dataIntegrityViolation_returns409_withoutDetails() throws Exception {
        ResultActions result = mockMvc.perform(get("/test/data-integrity"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Request conflicts with existing data"))
                .andExpect(jsonPath("$.timestamp").exists());

        assertThat(bodyOf(result)).doesNotContain("users_username_key");
    }

    @Test
    @DisplayName("ConstraintViolationException returns 400 with sorted 'field: message' entries")
    void constraintViolation_returns400_withSortedFieldMessages() throws Exception {
        mockMvc.perform(get("/test/constraint-violation"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(
                        "password: Password must be between 8 and 72 characters long; "
                                + "username: Username may only contain lowercase letters and digits; "
                                + "username: Username must be between 6 and 20 characters long"));
    }

    // ---------- security exceptions ----------

    @Test
    @DisplayName("AccessDeniedException returns 403 with a fixed message")
    void accessDenied_returns403_withFixedMessage() throws Exception {
        ResultActions result = mockMvc.perform(get("/test/access-denied"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("You do not have permission to access this resource"));

        assertThat(bodyOf(result)).doesNotContain("sensitive detail");
    }

    @Test
    @DisplayName("AuthenticationException returns 401 with a generic message")
    void authenticationFailure_returns401_withGenericMessage() throws Exception {
        ResultActions result = mockMvc.perform(get("/test/bad-credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));

        assertThat(bodyOf(result)).doesNotContain("secret detail");
    }

    @Test
    @DisplayName("InternalAuthenticationServiceException returns 500, not 401 (the specific handler wins)")
    void authServiceFailure_returns500_notTheGeneral401() throws Exception {
        // It is a subclass of AuthenticationException, so this proves the more specific
        // handler is chosen: a database outage during login must not look like a bad
        // password.
        ResultActions result = mockMvc.perform(get("/test/auth-service-failure"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Something went wrong"));

        assertThat(bodyOf(result)).doesNotContain("hunter2");
    }

    // ---------- catch-all ----------

    @Test
    @DisplayName("an exception that carries its own HTTP status keeps that status, with a generic message")
    void springErrorResponse_keepsItsStatus() throws Exception {
        ResultActions result = mockMvc.perform(get("/test/spring-error"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(HttpStatus.NOT_FOUND.getReasonPhrase()));

        assertThat(bodyOf(result)).doesNotContain("internal reason");
    }

    @Test
    @DisplayName("an unexpected exception returns 500 and hides its message")
    void unhandledException_returns500_withoutDetails() throws Exception {
        ResultActions result = mockMvc.perform(get("/test/unhandled"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Something went wrong"))
                .andExpect(jsonPath("$.timestamp").exists());

        assertThat(bodyOf(result)).doesNotContain("hunter2");
    }

    // ---------- helpers ----------

    /** Builds a real ConstraintViolationException by validating an invalid User. */
    private static ConstraintViolationException realViolations() {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        User invalid = new User("AB", "x", "Test User", UserRole.USER);
        return new ConstraintViolationException(validator.validate(invalid));
    }

    /** One endpoint per exception, so each test triggers exactly one handler. */
    @RestController
    @RequestMapping("/test")
    static class ThrowingController {

        @GetMapping("/not-found")
        String notFound() {
            throw USER_NOT_FOUND;
        }

        @GetMapping("/duplicate-username")
        String duplicateUsername() {
            throw DUPLICATE_USERNAME;
        }

        @GetMapping("/invalid-token")
        String invalidToken() {
            throw new InvalidTokenException(Reason.EXPIRED, "Token has expired");
        }

        @GetMapping("/data-integrity")
        String dataIntegrity() {
            throw new DataIntegrityViolationException(
                    "could not execute statement; constraint [users_username_key]");
        }

        @GetMapping("/constraint-violation")
        String constraintViolation() {
            throw realViolations();
        }

        @GetMapping("/access-denied")
        String accessDenied() {
            throw new AccessDeniedException("sensitive detail");
        }

        @GetMapping("/bad-credentials")
        String badCredentials() {
            throw new BadCredentialsException("secret detail");
        }

        @GetMapping("/auth-service-failure")
        String authServiceFailure() {
            throw new InternalAuthenticationServiceException("db password is hunter2");
        }

        @GetMapping("/spring-error")
        String springError() {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "internal reason");
        }

        @GetMapping("/unhandled")
        String unhandled() {
            throw new IllegalStateException("db password is hunter2");
        }
    }
}