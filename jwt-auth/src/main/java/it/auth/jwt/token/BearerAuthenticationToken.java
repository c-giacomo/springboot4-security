package it.auth.jwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

/** Bearer token: non autenticato (stringa JWT) -> autenticato (Jwt validato). */
public final class BearerAuthenticationToken extends AbstractAuthenticationToken {

    private final UserDetails principal;
    private final Jwt jwt;      // null finché non è validato
    private String token;       // credentials

    private BearerAuthenticationToken(String token, UserDetails principal, Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.principal = principal;
        this.jwt = jwt;
        super.setAuthenticated(jwt != null);
    }

    public static BearerAuthenticationToken unauthenticated(String token) {
        return new BearerAuthenticationToken(token, null, null, AuthorityUtils.NO_AUTHORITIES);
    }

    public static BearerAuthenticationToken authenticated(UserDetails principal, Jwt jwt) {
        return new BearerAuthenticationToken(null, principal, jwt, principal.getAuthorities());
    }

    @Override public Object getPrincipal() { return principal; }
    @Override public Object getCredentials() { return token; }
    public Jwt getJwt() { return jwt; }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.token = null;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Usa il factory authenticated(...)");
        }
        super.setAuthenticated(false);
    }
}
