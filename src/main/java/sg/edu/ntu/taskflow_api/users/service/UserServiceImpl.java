package sg.edu.ntu.taskflow_api.users.service;

import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.exception.UserNotFoundException;
import sg.edu.ntu.taskflow_api.users.exception.UsernameAlreadyExistsException;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public User getUserById(long id) {
        return userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    }

    @Override
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
    }

    private String normalize(String username) {
        return username.toLowerCase(Locale.ROOT); // ROOT avoids locale quirks such as Turkish dotless i
    }

    @Override
    public void createUser(User user) {
        String username = normalize(user.getUsername());

        // Check if the new username is already taken by another user
        userRepository.findByUsername(username).ifPresent(existingUserWithUsername -> {
            throw new UsernameAlreadyExistsException(username);
        });

        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);
    }

    @Override
    public User updateUser(long id, User user) throws UserNotFoundException {
        String username = normalize(user.getUsername());

        // Check if the user with the given ID exists before updating
        User existingUser = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));

        // Check if the new username is already taken by another user
        userRepository.findByUsername(username).ifPresent(existingUserWithUsername -> {
            if (existingUserWithUsername.getId() != id) {
                throw new UsernameAlreadyExistsException(username);
            }
        });

        existingUser.setName(user.getName());
        existingUser.setUsername(username);
        existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
        existingUser.setRole(user.getRole());

        userRepository.save(existingUser);
        return existingUser;
    }

    @Override
    public User updateUser(long id, String username, String name, UserRole role) throws UserNotFoundException {
        String updatedUsername = normalize(username);

        // Check if the user with the given ID exists before updating
        User existingUser = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));

        // Check if the new username is already taken by another user
        userRepository.findByUsername(updatedUsername).ifPresent(existingUserWithUsername -> {
            if (existingUserWithUsername.getId() != id) {
                throw new UsernameAlreadyExistsException(updatedUsername);
            }
        });

        existingUser.setName(name);
        existingUser.setUsername(updatedUsername);
        existingUser.setRole(role);

        userRepository.save(existingUser);
        return existingUser;
    }

    @Override
    public User updatePassword(long id, String password) throws UserNotFoundException {

        // Check if the user with the given ID exists before updating
        User existingUser = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));

        existingUser.setPassword(passwordEncoder.encode(password));

        userRepository.save(existingUser);
        return existingUser;
    }

    @Override
    public void deleteUser(long id) throws UserNotFoundException {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
        } else {
            throw new UserNotFoundException(id);
        }
    }
}
