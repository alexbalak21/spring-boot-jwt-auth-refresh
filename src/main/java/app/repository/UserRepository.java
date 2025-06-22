package app.repository;

import app.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Logger log = LoggerFactory.getLogger(UserRepository.class);

    default Optional<User> findByUsername(String username) {
        log.debug("Searching for user by username: {}", username);
        Optional<User> user = findUserByUsername(username);
        log.debug("User found by username '{}': {}", username, user.isPresent() ? "yes" : "no");
        return user;
    }

    // Changed from _findByUsername to findUserByUsername
    Optional<User> findUserByUsername(String username);

    default Boolean existsByUsername(String username) {
        log.debug("Checking if user exists with username: {}", username);
        boolean exists = existsByUsernameIgnoreCase(username);
        log.debug("User with username '{}' exists: {}", username, exists);
        return exists;
    }

    // Using Spring Data JPA naming convention
    Boolean existsByUsernameIgnoreCase(String username);
}