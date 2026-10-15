package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.SystemEnvironmentPropertySource;

/**
 * JwtServiceTest calls the constructor directly. This test lets Spring inject
 * the two key properties, so it checks the wiring: the property names, the
 * precedence, and that an environment variable named `JWT_PRIVATE_KEY_BASE64`
 * reaches jwt.private-key-base64 (the Railway case).
 *
 * It does not load application.properties. If that file maps the variables
 * under other names, check it separately.
 */
class JwtServiceWiringTest {

    private static String base64Pem;

    @BeforeAll
    static void makeKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                        .encodeToString(pair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        base64Pem = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
                .withUserConfiguration(JwtService.class)
                .withPropertyValues("jwt.expiration-ms=60000", "jwt.issuer=users-service", "jwt.audience=tasks-api");
    }

    @Test
    void keyFromAnEnvironmentVariable_loads() {
        runner()
                .withPropertyValues("jwt.private-key-path=")
                .withInitializer(context -> context.getEnvironment().getPropertySources().addLast(
                        new SystemEnvironmentPropertySource("fakeEnvironment",
                                Map.of("JWT_PRIVATE_KEY_BASE64", base64Pem))))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    String token = context.getBean(JwtService.class).generateToken("alice", 7L, List.of("ROLE_USER"));
                    assertThat(context.getBean(JwtService.class).extractClaims(token).userId()).isEqualTo(7L);
                });
    }

    @Test
    void keyFromAProperty_loadsWithAnEmptyPath() {
        runner()
                .withPropertyValues("jwt.private-key-base64=" + base64Pem, "jwt.private-key-path=")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void theBase64KeyWinsOverAPathThatDoesNotExist() {
        runner()
                .withPropertyValues("jwt.private-key-base64=" + base64Pem, "jwt.private-key-path=/does/not/exist.pem")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void withNeitherSource_startupFailsWithAClearMessage() {
        runner()
                .withPropertyValues("jwt.private-key-base64=", "jwt.private-key-path=")
                .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
                        .hasMessageContaining("Neither 'jwt.private-key-base64' nor 'jwt.private-key-path'"));
    }

    @Test
    void aBrokenVariable_stopsStartup() {
        runner()
                .withPropertyValues("jwt.private-key-base64=garbage", "jwt.private-key-path=")
                .run(context -> assertThat(context).hasFailed());
    }
}