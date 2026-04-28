package io.jenkins.plugins.jwt.auth.filter;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token for JWT Bearer token authentication.
 */
public class JwtBearerTokenAuthentication implements Authentication {

    private final String principal;
    private final String token;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Object details;
    private boolean authenticated;

    public JwtBearerTokenAuthentication(
            String principal, String token, Collection<? extends GrantedAuthority> authorities) {
        this.principal = principal;
        this.token = token;
        this.authorities = authorities;
        this.details = null;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated && !authenticated) {
            throw new IllegalArgumentException("Cannot set this token to authenticated");
        }
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return principal;
    }
}
