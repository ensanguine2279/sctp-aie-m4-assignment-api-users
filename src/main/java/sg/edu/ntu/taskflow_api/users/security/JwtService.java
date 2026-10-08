package sg.edu.ntu.taskflow_api.users.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

@Service
public class JwtService {

    private final long jwtExpirationMs;
    private final SecretKey signingKey;

    public JwtService(@Value("${jwt.secret}") String jwtSecret, @Value("${jwt.expiration-ms}") long jwtExpirationMs) {
        try {
            this.signingKey = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        } catch (WeakKeyException ex) {
            throw new IllegalStateException("jwt.secret must be at least 32 bytes for HS256", ex);
        }
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .setSubject(username) // Who the token is for
                .setIssuedAt(now) // When token was created
                .setExpiration(expiry) // When token expires
                .claim("roles", roles)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims parseToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException ex) {
            throw new InvalidTokenException(Reason.EXPIRED, "Token has expired", ex);
        } catch (SignatureException ex) {
            throw new InvalidTokenException(Reason.BAD_SIGNATURE, "Token signature is invalid", ex);
        } catch (MalformedJwtException | UnsupportedJwtException ex) {
            throw new InvalidTokenException(Reason.MALFORMED, "Token is malformed", ex);
        } catch (IllegalArgumentException ex) { // null or empty string
            throw new InvalidTokenException(Reason.EMPTY, "Token is missing", ex);
        } catch (JwtException ex) { // anything else from jjwt
            throw new InvalidTokenException(Reason.MALFORMED, "Token is invalid", ex);
        }
    }

    public ClaimsDto extractClaims(String token) {
        // parseClaimsJws validates the signature first, then decodes the payload.
        // If the token was tampered with, it throws an exception before reaching
        // getSubject().
        Claims claims = parseToken(token);

        String username = claims.getSubject();
        if (username == null || username.isBlank()) {
            throw new InvalidTokenException(Reason.MALFORMED, "Token has no subject");
        }

        Date expiration = claims.getExpiration();
        if (expiration == null) {
            throw new InvalidTokenException(Reason.MALFORMED, "Token has no expiry");
        }

        List<String> roles = extractRoles(claims);

        return new ClaimsDto(username, roles, expiration.getTime());
    }

    private List<String> extractRoles(Claims claims) {
        Object rolesClaim = claims.get("roles");
        if (!(rolesClaim instanceof List<?> roles)) {
            return List.of();
        }

        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(role -> role.startsWith("ROLE_"))
                .toList();
    }
}
