package app.service;


import app.dto.LoginRequest;
import app.dto.RegisterRequest;
import app.dto.TokenPair;
import app.model.User;
import app.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Transactional
    public void register(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new IllegalStateException("User with username " + registerRequest.getUsername() + " already exists");
        }

        User user = User
                .builder()
                .username(registerRequest.getUsername())
                .fullName(registerRequest.getFullName())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();

        userRepository.save(user);
    }

    public TokenPair login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())

        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtService.generateTokenPair(authentication);
    }
}