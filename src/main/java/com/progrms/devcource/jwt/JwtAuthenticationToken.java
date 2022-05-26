package com.progrms.devcource.jwt;

import lombok.ToString;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@ToString
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;

    private String credential;

    public JwtAuthenticationToken(Object principal, String credential) {
        super(null);
        super.setAuthenticated(false);

        this.principal = principal;
        this.credential = credential;
    }

    public JwtAuthenticationToken(Object principal, String credential, Collection<? extends GrantedAuthority> authorities) {
        super((authorities));
        super.setAuthenticated(true);

        this.principal = principal;
        this.credential = credential;
    }

    @Override
    public String  getCredentials() {
        return credential;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Cannot set this token to trusted");
        }
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credential = null;
    }
}
