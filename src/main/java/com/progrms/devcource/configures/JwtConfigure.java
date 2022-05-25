package com.progrms.devcource.configures;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "jwt")
public class JwtConfigure {

    private String header;

    private String issuer;

    private String clientSecret;

    private int expirySeconds;

}
