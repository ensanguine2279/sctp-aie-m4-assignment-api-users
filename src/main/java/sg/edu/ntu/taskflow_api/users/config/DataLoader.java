package sg.edu.ntu.taskflow_api.users.config;

import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.annotation.PostConstruct;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

@Profile("dev")
@Component
public class DataLoader {
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;

        public DataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
                this.userRepository = userRepository;
                this.passwordEncoder = passwordEncoder;
        }

        @PostConstruct
        public void loadData() {
                // Clear the database first
                userRepository.deleteAll();

                // Load sample users
                User user1 = new User("alice01", passwordEncoder.encode("abcd1234"), "Alice Ang", UserRole.USER);
                User user2 = new User("benny01", passwordEncoder.encode("abcd1234"), "Benny Boh", UserRole.MANAGER);
                User user3 = new User("charlie", passwordEncoder.encode("abcd1234"), "Charlie Chee", UserRole.MANAGER);
                User user4 = new User("donald", passwordEncoder.encode("abcd1234"), "Donald Du", UserRole.USER);

                List<User> users = List.of(user1, user2, user3, user4);
                users.forEach(userRepository::save);
        }
}
