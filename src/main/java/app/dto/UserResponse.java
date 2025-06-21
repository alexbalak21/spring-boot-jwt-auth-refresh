package app.dto;

import app.model.User;
import lombok.Builder;
import lombok.Data;

// UserResponse.java
@Data
@Builder
public class UserResponse {
    private Long id;
    private String username;
    private String fullName;
    private String role;

    public static UserResponse fromUser(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .fullName(user.getFullName())
                .role(user.getRole().name())
                .build();
    }
}