package app.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom authentication failure handler that provides detailed error responses
 * for different authentication failure scenarios.
 */
@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Authentication failed";
        int status = HttpStatus.UNAUTHORIZED.value();

        // Handle different types of authentication failures
        if (exception.getCause() instanceof UsernameNotFoundException ||
                (exception.getMessage() != null && exception.getMessage().contains("User not found"))) {
            // User doesn't exist
            status = HttpStatus.NOT_FOUND.value();
            errorMessage = "User not found";
        } else if (exception instanceof BadCredentialsException) {
            // User exists but password is wrong
            errorMessage = "Wrong password";
        } else if (exception instanceof InternalAuthenticationServiceException) {
            // Internal server error during authentication
            status = HttpStatus.INTERNAL_SERVER_ERROR.value();
            errorMessage = "Internal authentication error";
        }

        // Prepare error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", status);
        errorResponse.put("error", errorMessage);
        errorResponse.put("message", exception.getMessage());
        errorResponse.put("path", request.getRequestURI());

        // Send error response
        response.setStatus(status);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}