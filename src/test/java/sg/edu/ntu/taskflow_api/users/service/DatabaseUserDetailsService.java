package sg.edu.ntu.taskflow_api.users.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;
import sg.edu.ntu.taskflow_api.users.repository.UserRepository;

/**
 * Plain unit tests: no Spring context, UserRepository is mocked.
 *
 * The last group wires the service into a DaoAuthenticationProvider with a real
 * BCrypt encoder, which is what AuthenticationConfiguration builds for the
 * login endpoint, so it checks the whole "load user, check password, grant
 * role"
 * path without starting the application.
 */
@ExtendWith(MockitoExtension.class)
class DatabaseUserDetailsServiceTest {

    private static final String RAW_PASSWORD = "abcd1234";

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private DatabaseUserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private User user(String username, String storedPassword, UserRole role) {
        return new User(username, storedPassword, "Test User", role);
    }

    private DaoAuthenticationProvider provider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    // ---------- loadUserByUsername ----------

    @Test
    @DisplayName("an existing user is loaded with the stored password hash and a ROLE_ authority")
    void loadUserByUsername_existingUser_returnsUserDetails() {
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(user("alice01", "stored-bcrypt-hash", UserRole.ADMIN)));

        UserDetails details = userDetailsService.loadUserByUsername("alice01");

        assertThat(details.getUsername()).isEqualTo("alice01");
        // The stored hash is passed through untouched: it must not be encoded a second
        // time.
        assertThat(details.getPassword()).isEqualTo("stored-bcrypt-hash");
        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_ADMIN");
    }

    @ParameterizedTest
    @EnumSource(UserRole.class)
    @DisplayName("every role becomes a ROLE_-prefixed authority")
    void loadUserByUsername_mapsEveryRoleWithPrefix(UserRole role) {
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(user("alice01", "hash", role)));

        UserDetails details = userDetailsService.loadUserByUsername("alice01");

        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_" + role.name());
    }

    @Test
    @DisplayName("the account is always enabled, unlocked and unexpired")
    void loadUserByUsername_accountFlagsAreAllTrue() {
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(user("alice01", "hash", UserRole.USER)));

        UserDetails details = userDetailsService.loadUserByUsername("alice01");

        // There is no disabled/locked concept in the User entity yet.
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();
    }

    @Test
    @DisplayName("an unknown username throws UsernameNotFoundException")
    void loadUserByUsername_missingUser_throws() {
        when(userRepository.findByUsername("nobody01")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> userDetailsService.loadUserByUsername("nobody01"));
    }

    @Test
    @DisplayName("the username is looked up exactly as given: lowercasing is the caller's job")
    void loadUserByUsername_doesNotNormalizeUsername() {
        when(userRepository.findByUsername("Alice01")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> userDetailsService.loadUserByUsername("Alice01"));

        verify(userRepository).findByUsername("Alice01");
        verifyNoMoreInteractions(userRepository); // in particular, no second lookup for "alice01"
    }

    // ---------- the login path: service + DaoAuthenticationProvider + BCrypt
    // ----------

    @Test
    @DisplayName("login: the correct password authenticates and carries the user's role")
    void authenticate_correctPassword_succeedsWithRole() {
        String storedHash = passwordEncoder.encode(RAW_PASSWORD);
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(user("alice01", storedHash, UserRole.ADMIN)));

        Authentication result = provider()
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated("alice01", RAW_PASSWORD));

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getName()).isEqualTo("alice01");
        // Spring Security 7 also adds a FACTOR_PASSWORD authority recording how the
        // user
        // authenticated, so only the ROLE_ authorities are compared here.
        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .filteredOn(authority -> authority.startsWith("ROLE_"))
                .containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("login: a wrong password is rejected with BadCredentialsException")
    void authenticate_wrongPassword_throwsBadCredentials() {
        String storedHash = passwordEncoder.encode(RAW_PASSWORD);
        when(userRepository.findByUsername("alice01"))
                .thenReturn(Optional.of(user("alice01", storedHash, UserRole.ADMIN)));

        assertThrows(BadCredentialsException.class, () -> provider()
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated("alice01", "wrong-password")));
    }

    @Test
    @DisplayName("login: an unknown user looks exactly like a wrong password (BadCredentialsException)")
    void authenticate_unknownUser_throwsBadCredentials() {
        when(userRepository.findByUsername("nobody01")).thenReturn(Optional.empty());

        // Spring hides UsernameNotFoundException by default, so callers cannot tell
        // "no such user" from "wrong password". AuthController relies on this for its
        // generic 401.
        assertThrows(BadCredentialsException.class, () -> provider()
                .authenticate(UsernamePasswordAuthenticationToken.unauthenticated("nobody01", RAW_PASSWORD)));
    }
}