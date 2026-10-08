package sg.edu.ntu.taskflow_api.users.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;

import jakarta.validation.ConstraintViolationException;

import sg.edu.ntu.taskflow_api.users.entity.User;
import sg.edu.ntu.taskflow_api.users.entity.UserRole;

/**
 * Repository slice tests. @DataJpaTest boots only JPA components against an
 * in-memory database and rolls back each test, so tests don't affect each
 * other.
 */
@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestEntityManager em;

    private User alice;
    private User bobby;

    // Usernames must be 6-20 chars (@Size on User.username).
    private User buildUser(String username) {
        return new User(username, "hashed-password", "Test User", UserRole.USER);
    }

    @BeforeEach
    void setUp() {
        alice = em.persist(buildUser("alice01"));
        bobby = em.persist(buildUser("bobby01"));
        em.flush();
        em.clear(); // force later reads to hit the database, not the persistence context
    }

    // ---------- save ----------

    @Test
    @DisplayName("save assigns a generated id and persists the user")
    void save_assignsIdAndPersists() {
        User saved = userRepository.save(buildUser("charlie1"));

        assertThat(saved.getId()).isPositive();
        assertThat(userRepository.findByUsername("charlie1")).isPresent();
    }

    @Test
    @DisplayName("save rejects a duplicate username")
    void save_duplicateUsername_throws() {
        assertThrows(DataIntegrityViolationException.class,
                () -> userRepository.saveAndFlush(buildUser("alice01")));
    }

    @Test
    @DisplayName("save round-trips every field, including the role enum")
    void save_persistsAllFields() {
        User manager = new User("manager1", "pw-hash-1234", "Mary Manager", UserRole.MANAGER);
        User saved = userRepository.saveAndFlush(manager);
        em.clear();

        User found = userRepository.findById(saved.getId()).orElseThrow();

        assertThat(found.getUsername()).isEqualTo("manager1");
        assertThat(found.getPassword()).isEqualTo("pw-hash-1234");
        assertThat(found.getName()).isEqualTo("Mary Manager");
        assertThat(found.getRole()).isEqualTo(UserRole.MANAGER);
    }

    // ---------- bean validation (enforced on flush) ----------

    @Test
    @DisplayName("save rejects a username shorter than 6 characters")
    void save_usernameTooShort_throws() {
        User user = buildUser("abc");

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    @Test
    @DisplayName("save rejects a username longer than 20 characters")
    void save_usernameTooLong_throws() {
        User user = buildUser("a".repeat(21));

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    @Test
    @DisplayName("save rejects a blank password")
    void save_blankPassword_throws() {
        User user = buildUser("validuser");
        user.setPassword("  ");

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    @Test
    @DisplayName("save rejects a password shorter than 8 characters")
    void save_passwordTooShort_throws() {
        User user = buildUser("validuser");
        user.setPassword("short");

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    @Test
    @DisplayName("save rejects a blank name")
    void save_blankName_throws() {
        User user = buildUser("validuser");
        user.setName("");

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    @Test
    @DisplayName("save rejects a null role")
    void save_nullRole_throws() {
        User user = buildUser("validuser");
        user.setRole(null);

        assertThrows(ConstraintViolationException.class, () -> userRepository.saveAndFlush(user));
    }

    // ---------- findById ----------

    @Test
    @DisplayName("findById returns the user when it exists")
    void findById_existing_returnsUser() {
        Optional<User> found = userRepository.findById(alice.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("alice01");
    }

    @Test
    @DisplayName("findById returns empty when the id does not exist")
    void findById_missing_returnsEmpty() {
        assertThat(userRepository.findById(999_999L)).isEmpty();
    }

    // ---------- findByUsername ----------

    @Test
    @DisplayName("findByUsername returns the matching user")
    void findByUsername_existing_returnsUser() {
        Optional<User> found = userRepository.findByUsername("bobby01");

        assertThat(found).isPresent();
        assertThat(found.get().getId()).isEqualTo(bobby.getId());
    }

    @Test
    @DisplayName("findByUsername returns empty for an unknown username")
    void findByUsername_unknown_returnsEmpty() {
        assertThat(userRepository.findByUsername("nobody01")).isEmpty();
    }

    @Test
    @DisplayName("findByUsername is case-sensitive on H2")
    void findByUsername_isCaseSensitive() {
        // Depends on DB collation. Delete this test if your production DB
        // (e.g. MySQL) is case-insensitive.
        assertThat(userRepository.findByUsername("ALICE01")).isEmpty();
    }

    // ---------- findAll ----------

    @Test
    @DisplayName("findAll returns every persisted user")
    void findAll_returnsAllUsers() {
        List<User> users = userRepository.findAll();

        assertThat(users)
                .extracting(User::getUsername)
                .containsExactlyInAnyOrder("alice01", "bobby01");
    }

    @Test
    @DisplayName("findAll returns an empty list when there are no users")
    void findAll_empty_returnsEmptyList() {
        userRepository.deleteAll();
        em.flush();

        assertThat(userRepository.findAll()).isEmpty();
    }

    // ---------- existsById ----------

    @Test
    @DisplayName("existsById returns true for an existing id")
    void existsById_existing_returnsTrue() {
        assertThat(userRepository.existsById(alice.getId())).isTrue();
    }

    @Test
    @DisplayName("existsById returns false for a missing id")
    void existsById_missing_returnsFalse() {
        assertThat(userRepository.existsById(999_999L)).isFalse();
    }

    // ---------- deleteById ----------

    @Test
    @DisplayName("deleteById removes only the targeted user")
    void deleteById_existing_removesUser() {
        userRepository.deleteById(alice.getId());
        em.flush();
        em.clear();

        assertThat(userRepository.findByUsername("alice01")).isEmpty();
        assertThat(userRepository.findByUsername("bobby01")).isPresent();
    }

    @Test
    @DisplayName("deleteById with a missing id does not affect existing users")
    void deleteById_missing_leavesOthersUntouched() {
        userRepository.deleteById(999_999L);
        em.flush();

        assertThat(userRepository.findAll()).hasSize(2);
    }
}
