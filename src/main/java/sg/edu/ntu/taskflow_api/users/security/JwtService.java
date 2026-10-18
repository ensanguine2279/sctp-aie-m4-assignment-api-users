package sg.edu.ntu.taskflow_api.users.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    private static final String KEY_ERROR = "Failed to load JWT private key from Base64 environment variable";
    private static final Pattern PEM_LABEL = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");
    private static final int MIN_RSA_BITS = 2048;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final long jwtExpirationMs;
    private final String jwtIssuer;
    private final String jwtAudience;

    public JwtService(
            @Value("${jwt.private-key-base64}") String privateKeyBase64,
            @Value("${jwt.private-key-path}") String privateKeyPath,
            @Value("${jwt.expiration-ms}") long jwtExpirationMs,
            @Value("${jwt.issuer}") String jwtIssuer,
            @Value("${jwt.audience}") String jwtAudience) {

        // logger.info("Initializing JwtService with privateKeyBase64: {},
        // privateKeyPath: {}", privateKeyBase64,privateKeyPath);

        // 1. Prioritize Base64 Environment Variable (for Railway / Cloud)
        if (privateKeyBase64 != null && !privateKeyBase64.isBlank()) {
            this.privateKey = parsePrivateKeyFromBase64(privateKeyBase64);
        }
        // 2. Fallback to File Path (for Local Docker Compose / IDE)
        else if (privateKeyPath != null && !privateKeyPath.isBlank()) {
            // logger.info("Loading private key from path: {}", privateKeyPath);
            this.privateKey = PemKeyLoader.loadPrivateKey(privateKeyPath);
        } else {
            throw new IllegalArgumentException(
                    "Neither 'jwt.private-key-base64' nor 'jwt.private-key-path' is configured.");
        }

        requireStrongRsaKey(this.privateKey);
        this.publicKey = PemKeyLoader.derivePublicKey(privateKey);
        this.jwtExpirationMs = jwtExpirationMs;
        this.jwtIssuer = jwtIssuer;
        this.jwtAudience = jwtAudience;
    }

    /**
     * Accepts the key as an environment variable in either form people actually
     * paste:
     * the whole PEM file base64-encoded (line breaks tolerated), or the raw PEM
     * (leading and trailing whitespace tolerated, and literal "\\n" sequences,
     * which some platforms store instead of line breaks).
     *
     * Every failure message starts with KEY_ERROR and never contains any of the
     * key.
     */
    private PrivateKey parsePrivateKeyFromBase64(String base64Input) {
        String pemContent = decodeToPem(base64Input);
        requirePkcs8(pemContent);
        try {
            String cleanKey = pemContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException(KEY_ERROR, ex);
        }
    }

    private static String decodeToPem(String input) {
        String value = input.trim();
        if (value.startsWith("-----BEGIN")) {
            return value.replace("\\n", "\n");
        }
        try {
            // The MIME decoder ignores the line breaks that `base64` adds by default
            return new String(Base64.getMimeDecoder().decode(value), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(KEY_ERROR, ex);
        }
    }

    /**
     * Only an unencrypted PKCS#8 key ("BEGIN PRIVATE KEY") is accepted, as with the
     * file loader.
     */
    private static void requirePkcs8(String pem) {
        if (pem.contains("-----BEGIN PRIVATE KEY-----")) {
            return;
        }
        Matcher label = PEM_LABEL.matcher(pem);
        String detail;
        if (label.find()) {
            detail = "expected an unencrypted PKCS#8 key ('BEGIN PRIVATE KEY') but found '" + label.group(1) + "'";
            if ("RSA PRIVATE KEY".equals(label.group(1))) {
                detail += ". Convert it with: openssl pkcs8 -topk8 -nocrypt -in old.pem -out private.pem";
            }
        } else {
            detail = "the value is neither a PEM private key nor a base64-encoded one";
        }
        throw new IllegalArgumentException(KEY_ERROR + ": " + detail);
    }

    /**
     * jjwt refuses to sign RS256 with a smaller key, so fail at startup rather than
     * on the first login.
     */
    private static void requireStrongRsaKey(PrivateKey key) {
        if (!(key instanceof RSAKey rsa) || rsa.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalStateException(
                    "The JWT private key must be an RSA key of at least " + MIN_RSA_BITS + " bits");
        }
    }

    public String generateToken(String username, long userId, List<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .issuer(jwtIssuer) // Who issued the token
                .issuedAt(now) // When token was created
                .audience().add(jwtAudience).and() // Who the token is intended for
                .subject(username) // Who the token is for
                .claim("uid", userId) // The user's database id
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

    /**
     * The "uid" claim is required and must be a positive whole JSON number. A token
     * without one (for example issued before this claim existed) is rejected, the
     * same
     * rule the tasks API applies.
     */
    private long extractUserId(Claims claims) {
        Object uid = claims.get("uid");
        if (uid instanceof Number number) {
            long value = number.longValue();
            // The double comparison rejects 1.5 and numbers too large for a long.
            if (value > 0 && number.doubleValue() == (double) value) {
                return value;
            }
        }
        throw new InvalidTokenException(Reason.MALFORMED, "Token has no valid uid");
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

        long userId = extractUserId(claims);
        List<String> roles = extractRoles(claims);

        return new ClaimsDto(username, roles, expiration.getTime(), userId);
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