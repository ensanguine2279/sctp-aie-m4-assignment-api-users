package sg.edu.ntu.taskflow_api.users.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;

import sg.edu.ntu.taskflow_api.users.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(long id);

    Optional<User> findByUsername(String username);

    List<User> findAll();

    void deleteById(long id);

    boolean existsById(long id);
}
