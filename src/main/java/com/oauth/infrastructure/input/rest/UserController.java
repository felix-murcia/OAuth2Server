package com.oauth.infrastructure.input.rest;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oauth.application.in.CreateUserUseCase;
import com.oauth.application.in.GetUserUseCase;
import com.oauth.infrastructure.input.rest.dto.CreateUserDto;
import com.oauth.infrastructure.input.rest.dto.GetUserDto;
import com.oauth.infrastructure.input.rest.mapper.UserDtoMapper;

@RestController
@RequestMapping("/user")
public class UserController {

    private final CreateUserUseCase createUserUseCase;
    private final GetUserUseCase getUserUseCase;
    private final UserDtoMapper userDtoMapper;

    public UserController(CreateUserUseCase createUserUseCase,
            GetUserUseCase getUserUseCase,
            UserDtoMapper userDtoMapper) {
        this.createUserUseCase = createUserUseCase;
        this.getUserUseCase = getUserUseCase;
        this.userDtoMapper = userDtoMapper;
    }

    @PostMapping
    public GetUserDto nuevoUsuario(@RequestBody CreateUserDto newUser) {
        var user = userDtoMapper.toUserDomain(newUser);
        var result = createUserUseCase.execute(user);
        return userDtoMapper.toGetUserDto(result);
    }

    @GetMapping("/me")
    public GetUserDto me(@AuthenticationPrincipal org.springframework.security.core.userdetails.UserDetails authenticatedUser) {
        var result = getUserUseCase.findByUsername(authenticatedUser.getUsername());
        return userDtoMapper.toGetUserDto(result.orElseThrow());
    }
}
