package sg.edu.ntu.taskflow_api.users.security;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import sg.edu.ntu.taskflow_api.users.dto.ClaimsDto;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException;
import sg.edu.ntu.taskflow_api.users.exception.InvalidTokenException.Reason;

@Service
public class JwtService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final long jwtExpirationMs;
    private final String jwtIssuer;
    private final String jwtAudience;

    public JwtService(
            @Value("${jwt.private-key-path}") String privateKeyPath,
            @Value("${jwt.expiration-ms}") long jwtExpirationMs,
            @Value("${jwt.issuer}") String jwtIssuer,
            @Value("${jwt.audience}") String jwtAudience) {
        this.privateKey = PemKeyLoader.loadPrivateKey(privateKeyPath);
        this.publicKey = PemKeyLoader.derivePublicKey(privateKey);
        this.jwtExpirationMs = jwtExpirationMs;
        this.jwtIssuer = jwtIssuer;
        this.jwtAudience = jwtAudience;
    }

    public String generateToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .issuer(jwtIssuer) // Who issued the token
                .issuedAt(now) // When token was created
                .audience().add(jwtAudience).and() // Who the token is intended for
                .subject(username) // Who the token is for
                .expiration(expiry) // When the token will expire
                .claim("roles", roles) // The roles of the user
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(jwtIssuer)
                    .requireAudience(jwtAudience)
                    .clockSkewSeconds(30)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
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
