package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Pure unit tests: no Spring context. UserRepository is mocked.
 *
 * isSelf takes a primitive long, so it calls the primitive findById(long)
 * overload; stubs below use long literals to match.
 */
@ExtendWith(MockitoExtension.class)
class UserSecurityTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserSecurity userSecurity;

    private User buildUser(long id, String username) {
        User user = new User(username, "password1", "Test User", UserRole.USER);
        user.setId(id);
        return user;
    }

    @Test
    @DisplayName("isSelf returns true when the username matches the stored user")
    void isSelf_matchingUsername_returnsTrue() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(buildUser(1L, "alice01")));

        assertThat(userSecurity.isSelf(1L, "alice01")).isTrue();
    }

    @Test
    @DisplayName("isSelf returns false when the username belongs to someone else")
    void isSelf_differentUsername_returnsFalse() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(buildUser(1L, "alice01")));

        assertThat(userSecurity.isSelf(1L, "bobby01")).isFalse();
    }

    @Test
    @DisplayName("isSelf returns false when the user does not exist")
    void isSelf_missingUser_returnsFalse() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertThat(userSecurity.isSelf(99L, "alice01")).isFalse();
    }

    @Test
    @DisplayName("isSelf returns false when the caller's username is null")
    void isSelf_nullUsername_returnsFalse() {
        when(userRepository.findById(1L)).thenReturn(Optional.of(buildUser(1L, "alice01")));

        assertThat(userSecurity.isSelf(1L, null)).isFalse();
    }

    @Test
    @DisplayName("isSelf compares usernames case-sensitively")
    void isSelf_differentCase_returnsFalse() {
        // Stored usernames are lowercase, so a token carrying "Alice01" is not treated
        // as the same user.
        when(userRepository.findById(1L)).thenReturn(Optional.of(buildUser(1L, "alice01")));

        assertThat(userSecurity.isSelf(1L, "Alice01")).isFalse();
    }
}
