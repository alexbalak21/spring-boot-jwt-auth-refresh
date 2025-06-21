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

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Extract the Authorization header from the incoming request
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // If there is no Authorization header or it doesn't start with 'Bearer ', skip JWT authentication
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the token by removing the 'Bearer ' prefix
        jwt = authHeader.substring(7);

        // Extract the username from the JWT if possible
        username = jwtService.usernameFromToken(jwt).orElse(null);

        // Continue only if a username is found AND the SecurityContext has not already been authenticated
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load user details (credentials and authorities) from your user management system
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // Validate the token against the user details
            if (jwtService.validateToken(jwt, userDetails)) {

                // Create an authenticated token with user's authorities and attach request-specific details
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Store the authentication object in the SecurityContext, marking the request as authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

            // Proceed with the filter chain whether authentication was successful or not
            filterChain.doFilter(request, response);
        }
    }
}