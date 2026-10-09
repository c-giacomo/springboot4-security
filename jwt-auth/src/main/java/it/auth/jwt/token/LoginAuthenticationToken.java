package it.auth.jwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public final class LoginAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    private LoginAuthenticationToken(Object principal, Object credentials,
                                     Collection<? extends GrantedAuthority> authorities, boolean authenticated) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(authenticated);
    }

    public static LoginAuthenticationToken unauthenticated(String username, String password) {
        return new LoginAuthenticationToken(username, password, AuthorityUtils.NO_AUTHORITIES, false);
    }

    public static LoginAuthenticationToken authenticated(UserDetails user) {
        return new LoginAuthenticationToken(user, null, user.getAuthorities(), true);
    }

    @Override
    public Object getPrincipal() { return principal; }
    @Override
    public Object getCredentials() { return credentials; }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Usa il factory authenticated(...)");
        }
        super.setAuthenticated(false);
    }
}
