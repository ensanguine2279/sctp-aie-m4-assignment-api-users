package sg.edu.ntu.taskflow_api.users.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** Pure unit tests: no Spring context and no repository. The id comes from the token. */
class UserSecurityTest {

    private final UserSecurity userSecurity = new UserSecurity();

    private static Authentication caller(String username, long userId) {
        return UsernamePasswordAuthenticationToken.authenticated(
                new AuthenticatedUser(username, userId), null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Test
    @DisplayName("isSelf returns true when the caller's id matches")
    void isSelf_matchingId_returnsTrue() {
        assertThat(userSecurity.isSelf(1L, caller("alice01", 1L))).isTrue();
    }

    @Test
    @DisplayName("isSelf returns false when the id belongs to someone else")
    void isSelf_differentId_returnsFalse() {
        assertThat(userSecurity.isSelf(2L, caller("alice01", 1L))).isFalse();
    }

    @Test
    @DisplayName("isSelf compares ids, not usernames: the same username with another id is not self")
    void isSelf_sameUsernameDifferentId_returnsFalse() {
        assertThat(userSecurity.isSelf(99L, caller("alice01", 1L))).isFalse();
    }

    @Test
    @DisplayName("isSelf returns false when there is no authentication")
    void isSelf_nullAuthentication_returnsFalse() {
        assertThat(userSecurity.isSelf(1L, null)).isFalse();
    }

    @Test
    @DisplayName("isSelf fails closed for an unexpected principal type")
    void isSelf_unexpectedPrincipal_returnsFalse() {
        Authentication stringPrincipal = UsernamePasswordAuthenticationToken.authenticated(
                "alice01", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(userSecurity.isSelf(1L, stringPrincipal)).isFalse();
    }

    @Test
    @DisplayName("isSelf works for very large ids")
    void isSelf_largeId_returnsTrue() {
        long big = 5_000_000_000L;

        assertThat(userSecurity.isSelf(big, caller("alice01", big))).isTrue();
    }
}