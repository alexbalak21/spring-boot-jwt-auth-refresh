package app.filter;

import app.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A filter that intercepts incoming requests to validate JWT tokens in the Authorization header.
 * This filter is responsible for:
 * 1. Extracting the JWT token from the Authorization header
 * 2. Validating the token
 * 3. Loading user details if the token is valid
 * 4. Setting the authentication in the security context
 *
 * This filter extends OncePerRequestFilter to ensure it's only executed once per request.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * Service for JWT token operations.
     */
    private final JwtService jwtService;

    /**
     * Service for loading user details from the database.
     */
    private final UserDetailsService userDetailsService;

    /**
     * Constructs a new JwtAuthenticationFilter with the required dependencies.
     *
     * @param jwtService the JWT service for token validation and extraction
     * @param userDetailsService the service for loading user details
     */
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Processes each incoming request to validate JWT tokens.
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @param filterChain the filter chain to continue processing the request
     * @throws ServletException if an error occurs during the filter process
     * @throws IOException if an I/O error occurs during the filter process
     */
    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Extract the Authorization header from the incoming request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;  // Will hold the extracted JWT token
        final String username;  // Will hold the username extracted from the token

        // If there is no Authorization header or it doesn't start with 'Bearer ', skip JWT authentication
        // and continue with the next filter in the chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the token by removing the 'Bearer ' prefix (7 characters)
        jwt = authHeader.substring(7);

        // Extract the username from the JWT if possible
        // Returns null if the token is invalid or doesn't contain a username
        username = jwtService.usernameFromToken(jwt).orElse(null);

        // Continue with authentication only if:
        // 1. A username was successfully extracted from the token
        // 2. The SecurityContext doesn't already contain an authentication object
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load user details (including authorities) from the database
            // This will throw UsernameNotFoundException if the user is not found
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Validate the token against the user details
            // This checks both token validity and if it belongs to the specified user
            if (jwtService.validateToken(jwt, userDetails)) {

                // Create an authenticated token with the user's details and authorities
                // The credentials are set to null as we don't need them after authentication
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,  // Principal (the user)
                        null,         // Credentials (not needed after authentication)
                        userDetails.getAuthorities()  // User's roles/permissions
                );

                // Add request-specific details like IP address and session ID to the authentication
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Store the authentication object in the SecurityContext, marking the request as authenticated
                // This makes the authentication available throughout the request lifecycle
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

            // Always continue with the filter chain
            // If authentication failed, the request will be handled as unauthenticated
            // by Spring Security's authorization mechanisms
            filterChain.doFilter(request, response);
        }
    }
}