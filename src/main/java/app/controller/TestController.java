package app.controller;

import app.model.User;
import app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
@Slf4j
public class TestController {

    private final UserRepository userRepository;

    @GetMapping("/users")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        log.info("Fetching all users");
        List<User> users = userRepository.findAll();
        log.debug("Found {} users", users.size());
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{username}")
    public ResponseEntity<User> getUserByUsername(@PathVariable String username) {
        log.info("Fetching user by username: {}", username);
        return userRepository.findByUsername(username)
                .map(ResponseEntity::ok)
                .orElseGet(() -> {
                    log.warn("User not found with username: {}", username);
                    return ResponseEntity.notFound().build();
                });
    }

    @GetMapping("/ping")
    public String ping() {
        return "Server is running";
    }
}
