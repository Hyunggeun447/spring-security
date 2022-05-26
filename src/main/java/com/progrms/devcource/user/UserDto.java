package com.progrms.devcource.user;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
public class UserDto {

    private final String token;
    private final String username;
    private final String group;
}
