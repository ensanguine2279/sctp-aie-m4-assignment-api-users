package sg.edu.ntu.taskflow_api.users.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.exception.UserNotFoundException;
import sg.edu.ntu.taskflow_api.users.exception.UsernameAlreadyExistsException;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Pure unit tests: no Spring context, no database. UserRepository and
 * PasswordEncoder are mocked, so only UserServiceImpl's own logic is tested.
 *
 * Note: the service calls the primitive overloads (findById(long),
 * existsById(long), deleteById(long)), so stubs and verifications below use
 * primitive long values to match. Unstubbed repository calls return
 * Optional.empty() (Mockito's default for Optional), which is what
 * "username is free" looks like to the service.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private UserServiceImpl userService;

    private User buildUser(String username) {
        return new User(username, "password1", "Test User", UserRole.USER);
    }

    private User buildUserWithId(long id, String username) {
        User user = buildUser(username);
        user.setId(id);
        return user;
    }

    // ---------- getAllUsers ----------

    @Test
    @DisplayName("getAllUsers returns every user from the repository")
    void getAllUsers_returnsRepositoryResults() {
        List<User> users = List.of(buildUser("alice01"), buildUser("bobby01"));
        when(userRepository.findAll()).thenReturn(users);

        assertThat(userService.getAllUsers()).containsExactlyElementsOf(users);
    }

    @Test
    @DisplayName("getAllUsers returns an empty list when there are no users")
    void getAllUsers_noUsers_returnsEmptyList() {
        when(userRepository.findAll()).thenReturn(List.of());

        assertThat(userService.getAllUsers()).isEmpty();
    }

    // ---------- getUserById ----------

    @Test
    @DisplayName("getUserById returns the user when it exists")
    void getUserById_existing_returnsUser() {
        User alice = buildUser("alice01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(alice));

        assertThat(userService.getUserById(1L)).isSameAs(alice);
    }

    @Test
    @DisplayName("getUserById throws UserNotFoundException when the id does not exist")
    void getUserById_missing_throwsUserNotFound() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.getUserById(99L));
    }

    // ---------- getUserByUsername ----------

    @Test
    @DisplayName("getUserByUsername returns the matching user")
    void getUserByUsername_existing_returnsUser() {
        User alice = buildUser("alice01");
        when(userRepository.findByUsername("alice01")).thenReturn(Optional.of(alice));

        assertThat(userService.getUserByUsername("alice01")).isSameAs(alice);
    }

    @Test
    @DisplayName("getUserByUsername throws UserNotFoundException for an unknown username")
    void getUserByUsername_missing_throwsUserNotFound() {
        when(userRepository.findByUsername("nobody01")).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.getUserByUsername("nobody01"));
    }

    // ---------- createUser ----------

    @Test
    @DisplayName("createUser hashes the password before saving")
    void createUser_hashesPasswordAndSaves() {
        User user = buildUser("alice01"); // raw password: "password1"
        when(passwordEncoder.encode("password1")).thenReturn("hashed-password1");

        userService.createUser(user);

        verify(passwordEncoder).encode("password1");
        verify(userRepository).save(user);
        // The service mutates the passed-in user, so the saved object carries the hash.
        assertThat(user.getPassword()).isEqualTo("hashed-password1");
    }

    @Test
    @DisplayName("createUser stores the username in lowercase")
    void createUser_lowercasesUsername() {
        User user = buildUser("Alice01");
        when(passwordEncoder.encode("password1")).thenReturn("hashed-password1");

        userService.createUser(user);

        verify(userRepository).save(user);
        assertThat(user.getUsername()).isEqualTo("alice01");
    }

    @Test
    @DisplayName("createUser rejects a username that is already taken")
    void createUser_duplicateUsername_throwsAndDoesNotSave() {
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(buildUserWithId(1L, "alice01")));

        assertThrows(UsernameAlreadyExistsException.class,
                () -> userService.createUser(buildUser("alice01")));

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("createUser rejects a duplicate that differs only by case")
    void createUser_duplicateDifferentCase_throwsAndDoesNotSave() {
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(buildUserWithId(1L, "alice01")));

        assertThrows(UsernameAlreadyExistsException.class,
                () -> userService.createUser(buildUser("Alice01")));

        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    // ---------- updateUser ----------

    @Test
    @DisplayName("updateUser copies name, username and role, hashes the password, and saves")
    void updateUser_existing_updatesFieldsAndSaves() {
        User existing = buildUserWithId(1L, "alice01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(passwordEncoder.encode("newpass1")).thenReturn("hashed-newpass1");

        User changes = new User("alice02", "newpass1", "Alice Updated", UserRole.MANAGER);

        User result = userService.updateUser(1L, changes);

        assertThat(result).isSameAs(existing);
        assertThat(result.getUsername()).isEqualTo("alice02");
        assertThat(result.getName()).isEqualTo("Alice Updated");
        assertThat(result.getRole()).isEqualTo(UserRole.MANAGER);
        assertThat(result.getPassword()).isEqualTo("hashed-newpass1");
        verify(userRepository).save(existing);
    }

    @Test
    @DisplayName("updateUser never stores the raw password")
    void updateUser_doesNotStoreRawPassword() {
        User existing = buildUserWithId(1L, "alice01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(passwordEncoder.encode("newpass1")).thenReturn("hashed-newpass1");

        User result = userService.updateUser(1L, new User("alice02", "newpass1", "Test User", UserRole.USER));

        assertThat(result.getPassword()).isNotEqualTo("newpass1");
    }

    @Test
    @DisplayName("updateUser allows a user to keep their own username")
    void updateUser_sameUsername_isAllowed() {
        User existing = buildUserWithId(1L, "alice01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        // The username lookup finds the user themselves, which must not count as a
        // clash.
        when(userRepository.findByUsername("alice01")).thenReturn(Optional.of(existing));
        when(passwordEncoder.encode("newpass1")).thenReturn("hashed-newpass1");

        User result = userService.updateUser(1L, new User("alice01", "newpass1", "New Name", UserRole.USER));

        assertThat(result.getUsername()).isEqualTo("alice01");
        assertThat(result.getName()).isEqualTo("New Name");
        verify(userRepository).save(existing);
    }

    @Test
    @DisplayName("updateUser stores the username in lowercase")
    void updateUser_lowercasesUsername() {
        User existing = buildUserWithId(1L, "alice01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(passwordEncoder.encode("newpass1")).thenReturn("hashed-newpass1");

        User result = userService.updateUser(1L, new User("Alice02", "newpass1", "Test User", UserRole.USER));

        assertThat(result.getUsername()).isEqualTo("alice02");
    }

    @Test
    @DisplayName("updateUser rejects a username that belongs to a different user")
    void updateUser_usernameTakenByAnotherUser_throwsAndDoesNotSave() {
        User existing = buildUserWithId(1L, "alice01");
        User someoneElse = buildUserWithId(2L, "bobby01");
        when(userRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(userRepository.findByUsername("bobby01")).thenReturn(Optional.of(someoneElse));

        assertThrows(UsernameAlreadyExistsException.class,
                () -> userService.updateUser(1L, new User("bobby01", "newpass1", "Test User", UserRole.USER)));

        assertThat(existing.getUsername()).isEqualTo("alice01"); // unchanged
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("updateUser throws UserNotFoundException and saves nothing when the id is missing")
    void updateUser_missing_throwsAndDoesNotSave() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class,
                () -> userService.updateUser(99L, buildUser("alice01")));

        verify(userRepository, never()).findByUsername(anyString());
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    // ---------- deleteUser ----------

    @Test
    @DisplayName("deleteUser deletes the user when it exists")
    void deleteUser_existing_deletesById() {
        when(userRepository.existsById(1L)).thenReturn(true);

        userService.deleteUser(1L);

        verify(userRepository).deleteById(1L);
    }

    @Test
    @DisplayName("deleteUser throws UserNotFoundException and deletes nothing when the id is missing")
    void deleteUser_missing_throwsAndDoesNotDelete() {
        when(userRepository.existsById(99L)).thenReturn(false);

        assertThrows(UserNotFoundException.class, () -> userService.deleteUser(99L));

        verify(userRepository, never()).deleteById(anyLong());
    }
}