package sg.edu.ntu.taskflow_api.users.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Locale;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import sg.edu.ntu.taskflow_api.users.security.JwtService;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.dto.JwtValidationRequestDto;
import sg.edu.ntu.taskflow_api.users.dto.LoginRequestDto;
import sg.edu.ntu.taskflow_api.users.dto.TokenResponseDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService) {
        logger.info("AuthController initialized with AuthenticationManager and JwtService");
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@RequestBody @Valid LoginRequestDto request) {
        String username = request.getUsername().toLowerCase(Locale.ROOT);

        // Sanitize the username to prevent log injection/forging attacks
        String logUsername = username.replaceAll("\\p{Cc}", "_"); // all control characters, not just \r \n \t

        try {

            logger.info("Login attempt for user: {}", logUsername);

            // Delegate credential validation to Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, request.getPassword()));

            List<String> roles = authentication.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .filter(role -> role.startsWith("ROLE_"))
                    .toList();

            // If authentication succeeds, generate and return a token with claims
            String token = jwtService.generateToken(username, roles);
            ClaimsDto claims = jwtService.extractClaims(token);

            logger.debug("Generated claims for user: {}", claims);

            return ResponseEntity.ok(TokenResponseDto.builder()
                    .token(token)
                    .valid(true)
                    .claims(claims)
                    .build());

        } catch (InternalAuthenticationServiceException ex) {

            // so the catch-all returns a 500 with a stack trace:
            throw ex;
        } catch (AuthenticationException ex) {
            // InternalAuthenticationServiceException is a subclass of
            // AuthenticationException, so a database
            // outage during login is logged as a failed attempt and returns 401. Catch it
            // first, rethrow it,
            // and let the GlobalExceptionHandler handle it
            if (!(ex instanceof InternalAuthenticationServiceException)) {
                logger.warn("Failed login attempt for user: {}", logUsername);
            }
            throw ex; // GlobalExceptionHandler decides the response
        }
    }

    @PostMapping("/validate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<TokenResponseDto> validateToken(@RequestBody JwtValidationRequestDto request) {
        try {
            return ResponseEntity.ok(TokenResponseDto.builder()
                    .token(request.token())
                    .valid(true)
                    .claims(jwtService.extractClaims(request.token()))
                    .build());
        } catch (InvalidTokenException ex) {
            return ResponseEntity.ok(TokenResponseDto.builder()
                    .token(request.token())
                    .valid(false)
                    .error(ex.getReason().name())
                    .build());
        }
    }
}