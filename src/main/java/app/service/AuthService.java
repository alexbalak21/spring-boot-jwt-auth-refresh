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
import lombok.RequiredArgsConstructor;
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

/**
 * Service responsible for handling authentication-related operations including user registration,
 * login, and token refresh. This service acts as the core business logic layer for authentication
 * and works in conjunction with Spring Security.
 *
 * <p>Key responsibilities include:
 * <ul>
 *   <li>User registration with proper validation and role assignment</li>
 *   <li>User authentication using Spring Security's AuthenticationManager</li>
 *   <li>JWT token generation and refresh token handling</li>
 *   <li>User details management and validation</li>
 * </ul>
 *
 * @see org.springframework.security.authentication.AuthenticationManager
 * @see JwtService
 * @see UserDetailsService
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final CustomBlacklistAuthToken authTokenBlacklistService;
    private final CustomBlacklistRefreshToken refreshTokenBlacklistService;


    /**
     * Registers a new user with the provided registration details.
     * Validates the uniqueness of the username and encodes the password before storage.
     *
     * @param request The registration request containing user details
     * @return The newly created and persisted User entity
     * @throws RuntimeException If the username is already taken
     * @throws IllegalArgumentException If the request is invalid
     */
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
        user.setEmail(request.getEmail());
        user.setRole(request.getRole()); // This will now call getRole() which does the conversion

        User savedUser = userRepository.save(user);
        log.info("Successfully registered user: {} with role: {}", savedUser.getUsername(), savedUser.getRole());

        return savedUser;
    }

    /**
     * Authenticates a user and generates JWT tokens upon successful authentication.
     *
     * @param loginRequest The login request containing username and password
     * @return TokenPair containing both access and refresh tokens
     * @throws BadCredentialsException If authentication fails due to invalid credentials
     * @throws AuthenticationException For other authentication failures
     */
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

    /**
     * Refreshes an access token using a valid refresh token.
     * Validates the refresh token and issues a new token pair if valid.
     *
     * @param request The refresh token request containing the refresh token
     * @return New TokenPair with fresh access and refresh tokens
     * @throws IllegalArgumentException If the refresh token is invalid or expired
     * @throws UsernameNotFoundException If the user associated with the token is not found
     */
    public TokenPair refreshTokens(@Valid RefreshTokenRequest request) {
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

        //Creates a new authentication token
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                user, null
                , user.getAuthorities()
        );
        return jwtService.generateTokenPair(authentication);
    }

    /**
     * Logs out the current user by blacklisting the current access token and refresh token.
     * This effectively invalidates both tokens, requiring the user to log in again.
     *
     * @param accessToken The current access token to blacklist
     * @param refreshToken The current refresh token to blacklist
     * @throws IllegalArgumentException If either token is invalid or expired
     */

    //NEED TO SEE WHY THIS IS NOT WORKING
    //AUTHTOKEN GETTING BLACKLISTED BUT REFRESHTOKEN IS NOT
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        if (accessToken == null || accessToken.isBlank()) {
            log.warn("Access token is required for logout");
            throw new IllegalArgumentException("Access token is required");
        }

        // Blacklist the access token
        authTokenBlacklistService.blacklistToken(accessToken);

        // Blacklist the refresh token
        if (refreshToken == null || refreshToken.isBlank()) {
            log.warn("Refresh token is required for logout");
            throw new IllegalArgumentException("Refresh token is required");
        }
        refreshTokenBlacklistService.blackListToken(refreshToken);
        
        // Clear the security context
        SecurityContextHolder.clearContext();
    }
}