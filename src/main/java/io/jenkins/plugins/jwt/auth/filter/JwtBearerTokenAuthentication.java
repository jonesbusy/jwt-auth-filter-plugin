package io.jenkins.plugins.jwt.auth.filter;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Authentication token for JWT Bearer token authentication.
 */
public class JwtBearerTokenAuthentication implements Authentication {

    private final String principal;
    private final Collection<? extends GrantedAuthority> authorities;
    private boolean authenticated;

    public JwtBearerTokenAuthentication(String principal, Collection<? extends GrantedAuthority> authorities) {
        this.principal = principal;
        this.authorities = authorities;
        this.authenticated = true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null; // Not used by Jenkins
    }

    @Override
    public Object getDetails() {
        return null; // Not used by Jenkins
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
