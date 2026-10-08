package sg.edu.ntu.taskflow_api.users.config;

import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Creates the first ADMIN user on startup, so a fresh database is usable
 * (creating users needs an admin token, and logging in needs a user).
 *
 * It does nothing unless BOTH app.seed-admin.username and
 * app.seed-admin.password
 * are set, and it never touches a database that already has users.
 */
@Component
public class AdminSeeder implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(AdminSeeder.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String password;

    public AdminSeeder(UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.seed-admin.username:}") String username,
            @Value("${app.seed-admin.password:}") String password) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.username = username;
        this.password = password;
    }

    @Override
    public void run(String... args) {
        if (username.isBlank() || password.isBlank()) {
            return; // seeding not requested
        }
        if (userRepository.count() > 0) {
            return; // only seed an empty database
        }

        // The entity only sees the hash, so enforce the registration password policy
        // here.
        if (password.length() < 8 || password.length() > 72) {
            throw new IllegalStateException("app.seed-admin.password must be between 8 and 72 characters long");
        }

        // The username rules (6-20 lowercase letters/digits) are enforced by User's
        // validation on save.
        User admin = new User(username.toLowerCase(Locale.ROOT),
                passwordEncoder.encode(password),
                "Administrator",
                UserRole.ADMIN);
        userRepository.save(admin);

        logger.info("Seeded initial admin user '{}'", admin.getUsername());
    }
}
