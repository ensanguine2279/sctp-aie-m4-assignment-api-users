package sg.edu.ntu.taskflow_api.users.security;

import org.springframework.stereotype.Component;

import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

@Component("userSecurity")
public class UserSecurity {
    private final UserRepository userRepository;

    public UserSecurity(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean isSelf(long id, String username) {
        return userRepository.findById(id)
                .map(u -> u.getUsername().equals(username))
                .orElse(false);
    }
}