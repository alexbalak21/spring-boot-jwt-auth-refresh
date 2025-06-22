package app.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;

@Slf4j
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // Only log for login endpoint
        if (request.getRequestURI().equals("/api/auth/login")) {
            ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request);
            
            // Log request details
            log.info("Request URL: {} {}", request.getMethod(), request.getRequestURL());
            log.info("Content-Type: {}", request.getContentType());
            log.info("Content-Length: {}", request.getContentLength());
            
            // Continue processing the request
            filterChain.doFilter(wrappedRequest, response);
            
            // After request is processed, log the body if it was a POST
            if ("POST".equalsIgnoreCase(request.getMethod())) {
                byte[] buf = wrappedRequest.getContentAsByteArray();
                if (buf.length > 0) {
                    String payload = new String(buf, 0, buf.length, wrappedRequest.getCharacterEncoding());
                    log.info("Request payload: {}", payload);
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
