package app.service;

import app.model.User;
import app.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

/**
 * Custom implementation of Spring Security's UserDetailsService.
 * This service is used by Spring Security to load user-specific data during authentication.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    // Injects the UserRepository to access user data from the database
    private final UserRepository userRepository;

    /**
     * Locates the user based on the username.
     * This method is called by Spring Security during authentication.
     *
     * @param username the username identifying the user whose data is required.
     * @return a fully populated UserDetails object (username, password, authorities).
     * @throws UsernameNotFoundException if the user could not be found.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Look up user in the database
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Return a Spring Security UserDetails object with user's credentials and roles
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),       // username
                user.getPassword(),       // hashed password
                getAuthorities(user)      // user's roles/authorities
        );
    }

    /**
     * Extracts the roles or authorities of the user.
     *
     * @param user the authenticated user entity
     * @return a collection of GrantedAuthority based on the user's role
     */
    private Collection<? extends GrantedAuthority> getAuthorities(User user) {
        // Converts the user's role enum to a SimpleGrantedAuthority
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().name());
        return List.of(authority);
    }
}