package com.SecurityTesting.Security.User.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String FirstName;
    private String LatName;
    private String email;
    private String password;
}
