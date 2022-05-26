package com.progrms.devcource.jwt;

import lombok.ToString;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.logging.log4j.util.Strings.isNotEmpty;

@ToString
public class JwtAuthentication {

    public final String token;

    public final String username;

    public JwtAuthentication(String token, String username) {
        checkArgument(isNotEmpty(token), "token must be provided");
        checkArgument(isNotEmpty(username), "username must be provided");

        this.token = token;
        this.username = username;
    }


}
