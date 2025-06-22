package app.service;

import app.dto.LoginRequest;
import app.dto.RegisterRequest;
import app.dto.TokenPair;
import app.model.Role;
import app.model.User;
import app.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@AllArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Transactional
    public User register(RegisterRequest request) {
        log.info("Registering new user with username: {}", request.getUsername());
        
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Username {} is already taken", request.getUsername());
            throw new RuntimeException("Username is already taken");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFullName(request.getFullName());
        user.setRole(request.getRole()); // This will now call getRole() which does the conversion

        User savedUser = userRepository.save(user);
        log.info("Successfully registered user: {} with role: {}", savedUser.getUsername(), savedUser.getRole());
        
        return savedUser;
    }

    public TokenPair login(LoginRequest loginRequest) {
        log.info("Attempting to authenticate user: '{}'", loginRequest.getUsername());
        
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Authentication successful for user: '{}'", loginRequest.getUsername());
            return jwtService.generateTokenPair(authentication);
        } catch (BadCredentialsException e) {
            log.error("Authentication failed - invalid credentials for user: {}", loginRequest.getUsername());
            throw new BadCredentialsException("Invalid username or password");
        } catch (Exception e) {
            log.error("Authentication failed for user '{}': {}", loginRequest.getUsername(), e.getMessage());
            throw new BadCredentialsException("Authentication failed");
        }
    }
}