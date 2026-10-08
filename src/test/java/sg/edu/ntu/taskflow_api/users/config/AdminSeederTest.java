package sg.edu.ntu.taskflow_api.users.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Plain unit tests: no Spring context. The seeder's username and password are
 * constructor arguments (not mockable collaborators), so it is built directly.
 */
@ExtendWith(MockitoExtension.class)
class AdminSeederTest {

    private static final String PASSWORD = "admin-pass-1";

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AdminSeeder seeder(String username, String password) {
        return new AdminSeeder(userRepository, passwordEncoder, username, password);
    }

    // ---------- seeding ----------

    @Test
    @DisplayName("an empty database gets an ADMIN user with a hashed password")
    void run_emptyDatabase_createsAdmin() {
        when(userRepository.count()).thenReturn(0L);
        when(passwordEncoder.encode(PASSWORD)).thenReturn("hashed-password");

        seeder("admin01", PASSWORD).run();

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo("admin01");
        assertThat(saved.getPassword()).isEqualTo("hashed-password").isNotEqualTo(PASSWORD);
        assertThat(saved.getName()).isEqualTo("Administrator");
        assertThat(saved.getRole()).isEqualTo(UserRole.ADMIN);
    }

    @Test
    @DisplayName("the username is stored in lowercase")
    void run_lowercasesUsername() {
        when(userRepository.count()).thenReturn(0L);
        when(passwordEncoder.encode(PASSWORD)).thenReturn("hashed-password");

        seeder("Admin01", PASSWORD).run();

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getUsername()).isEqualTo("admin01");
    }

    @ParameterizedTest
    @ValueSource(ints = { 8, 72 })
    @DisplayName("passwords at the 8 and 72 character limits are accepted")
    void run_passwordAtLimits_isAccepted(int length) {
        String password = "a".repeat(length);
        when(userRepository.count()).thenReturn(0L);
        when(passwordEncoder.encode(password)).thenReturn("hashed-password");

        seeder("admin01", password).run();

        verify(userRepository).save(any(User.class));
    }

    // ---------- when nothing should happen ----------

    @Test
    @DisplayName("a database that already has users is left alone")
    void run_existingUsers_doesNothing() {
        when(userRepository.count()).thenReturn(3L);

        seeder("admin01", PASSWORD).run();

        verify(userRepository, never()).save(any(User.class));
        verifyNoInteractions(passwordEncoder);
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "   " })
    @DisplayName("a blank username means seeding was not requested")
    void run_blankUsername_doesNothing(String username) {
        seeder(username, PASSWORD).run();

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "   " })
    @DisplayName("a blank password means seeding was not requested")
    void run_blankPassword_doesNothing(String password) {
        seeder("admin01", password).run();

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    // ---------- password policy ----------

    @ParameterizedTest
    @ValueSource(ints = { 1, 7, 73, 100 })
    @DisplayName("a password outside 8 to 72 characters stops startup with a clear message")
    void run_invalidPasswordLength_throws(int length) {
        when(userRepository.count()).thenReturn(0L);

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> seeder("admin01", "a".repeat(length)).run());

        assertThat(ex.getMessage()).contains("between 8 and 72");
        verify(userRepository, never()).save(any(User.class));
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("a bad password setting is ignored once users exist, so a leftover variable cannot block startup")
    void run_existingUsersAndInvalidPassword_doesNotThrow() {
        when(userRepository.count()).thenReturn(5L);

        assertDoesNotThrow(() -> seeder("admin01", "short").run());

        verify(userRepository, never()).save(any(User.class));
    }
}