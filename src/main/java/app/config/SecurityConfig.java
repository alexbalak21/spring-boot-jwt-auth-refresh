package app.config;

import app.filter.JwtAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Defines the password encoder used for encoding and verifying user passwords.
     * BCrypt is a strong hashing algorithm suitable for securing credentials.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures the primary Spring Security filter chain for the application.
     * This method defines how incoming HTTP requests are secured, authenticated, and processed.
     * Instead of using deprecated security beans, it leverages Spring Security's modern, declarative approach.
     * Highlights:
     * - Disables CSRF protection (common for stateless REST APIs).
     * - Permits unauthenticated access to /api/auth/** endpoints (e.g., login/register).
     * - Requires authentication for all other endpoints.
     * - Uses the custom UserDetailsService to load user credentials from the database.
     * - Enables HTTP Basic authentication for simple credential exchange via headers.
     *
     * @param http The HttpSecurity object used to build the security configuration.
     * @return A configured SecurityFilterChain bean that Spring uses to enforce security rules.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Disable CSRF protection — typically done for APIs that don't use cookies or sessions.
                // You may want to enable this for stateful web applications or add CSRF tokens instead.
                .csrf(csrf -> csrf.disable())

                // Disable session management for stateless APIs.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Use JWT for authentication.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // Define which endpoints require authentication and which are publicly accessible.
                .authorizeHttpRequests(requests -> requests
                        // Allow unauthenticated access to authentication-related endpoints like login or registration.
                        .requestMatchers("/api/auth/**").permitAll()

                        // Require authentication for any other endpoints not explicitly permitted.
                        .anyRequest().authenticated()
                )

                // Assign your custom UserDetailsService implementation.
                // Spring Security will use this to load user details (username, roles, password, etc.)
                // during the authentication process.
                .userDetailsService(userDetailsService)

                // Enable HTTP Basic authentication with default settings.
                // This means clients must send credentials in the Authorization header on each request.
                // Suitable for simple API interactions or tools like Postman.
                .httpBasic(Customizer.withDefaults())

                // Finalize the configuration and return the built security filter chain.
                .build();
    }
}