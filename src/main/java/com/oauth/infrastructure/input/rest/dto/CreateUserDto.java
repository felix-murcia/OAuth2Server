package com.oauth.infrastructure.input.rest.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserDto {
    private String username;
    private String fullName;
    private String email;
    private String password;
    private String password2;
}
