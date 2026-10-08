package sg.edu.ntu.taskflow_api.users.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public DatabaseUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));

        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().name())
                .build();
    }
}
