package it.auth.jwt.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

/** Bearer token: non autenticato (stringa JWT) -> autenticato (Jwt validato). */
public final class BearerAuthenticationToken extends AbstractAuthenticationToken {

    private final Jwt jwt;      // null finché non è validato
    private String token;       // credentials

    private BearerAuthenticationToken(String token, Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.jwt = jwt;
        super.setAuthenticated(jwt != null);
    }

    public static BearerAuthenticationToken unauthenticated(String token) {
        return new BearerAuthenticationToken(token, null, AuthorityUtils.NO_AUTHORITIES);
    }

    public static BearerAuthenticationToken authenticated(Jwt jwt, Collection<? extends GrantedAuthority> authorities) {
        return new BearerAuthenticationToken(null, jwt, authorities);
    }

    @Override
    public Object getPrincipal() { return jwt; }
    @Override
    public Object getCredentials() { return token; }
    @Override
    public String getName() { return jwt != null ? jwt.getSubject() : ""; }

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
