package sg.edu.ntu.taskflow_api.users.exception;

import java.util.stream.Collectors;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.ErrorResponse;

import jakarta.validation.ConstraintViolationException;

import sg.edu.ntu.taskflow_api.users.dto.ErrorResponseDto;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({ UserNotFoundException.class })
    public ResponseEntity<ErrorResponseDto> handleEntityNotFoundException(UserNotFoundException ex) {
        ErrorResponseDto errorResponse = new ErrorResponseDto(ex.getMessage(), Instant.now());
        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<ErrorResponseDto> handleUsernameAlreadyExistsException(UsernameAlreadyExistsException ex) {
        ErrorResponseDto errorResponse = new ErrorResponseDto(ex.getMessage(), Instant.now());
        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorResponseDto> handleInvalidToken(InvalidTokenException ex) {
        return new ResponseEntity<>(new ErrorResponseDto(ex.getMessage(), Instant.now()),
                HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseDto> handleAccessDenied(AccessDeniedException ex) {
        ErrorResponseDto errorResponse = new ErrorResponseDto("You do not have permission to access this resource",
                Instant.now());
        return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField() + ": " + e.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return new ResponseEntity<>(new ErrorResponseDto(message, Instant.now()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponseDto> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return new ResponseEntity<>(
                new ErrorResponseDto("Invalid value for '" + ex.getName() + "'", Instant.now()),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponseDto> handleUnreadable(HttpMessageNotReadableException ex) {
        return new ResponseEntity<>(new ErrorResponseDto("Malformed request body", Instant.now()),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponseDto> handleConstraintViolation(ConstraintViolationException ex) {
        String message = ex.getConstraintViolations().stream()
                .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                .sorted()
                .collect(Collectors.joining("; "));
        return new ResponseEntity<>(new ErrorResponseDto(message, Instant.now()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponseDto> handleConflict(DataIntegrityViolationException ex) {
        logger.warn("Data integrity violation: {}", ex.getMostSpecificCause().getMessage());
        return new ResponseEntity<>(new ErrorResponseDto("Request conflicts with existing data", Instant.now()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<ErrorResponseDto> handleAuthServiceFailure(InternalAuthenticationServiceException ex) {
        logger.error("Authentication service failure", ex);
        return new ResponseEntity<>(new ErrorResponseDto("Something went wrong", Instant.now()),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponseDto> handleAuthentication(AuthenticationException ex) {
        return new ResponseEntity<>(new ErrorResponseDto("Authentication failed", Instant.now()),
                HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDto> handleException(Exception ex) {
        if (ex instanceof ErrorResponse springError) {
            HttpStatus status = HttpStatus.valueOf(springError.getStatusCode().value());
            return new ResponseEntity<>(new ErrorResponseDto(status.getReasonPhrase(), Instant.now()), status);
        }
        logger.error("Unhandled exception", ex);
        return new ResponseEntity<>(new ErrorResponseDto("Something went wrong", Instant.now()),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
