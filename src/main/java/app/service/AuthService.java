package app.service;

import app.dto.LoginRequest;
import app.dto.RefreshTokenRequest;
import app.dto.RegisterRequest;
import app.dto.TokenPair;
import app.model.Role;
import app.model.User;
import app.repository.UserRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@AllArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


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

    public TokenPair refreshToken(@Valid RefreshTokenRequest request) {

        String token = request.getRefreshToken();
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Refresh token is required");
        }

        if (!jwtService.isTokenValid(token, true)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        //Stores usernameOpt in an optional variable
        Optional<String> usernameOpt = jwtService.usernameFromToken(token, true);

        //chacks if Refresh token returns username
        if (usernameOpt.isEmpty()) {
            throw new IllegalArgumentException("Username not found in refresh token");
        }
        String username = usernameOpt.get();
        //Checks if user exists in database
        UserDetails user = userDetailsService.loadUserByUsername(username);
        if (user == null) {
            throw new IllegalArgumentException("User not found");
        }
        log.info("Refreshing token for user: '{}'", username);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user, null
                , user.getAuthorities()
        );
        return jwtService.generateTokenPair(authentication);
    }
}