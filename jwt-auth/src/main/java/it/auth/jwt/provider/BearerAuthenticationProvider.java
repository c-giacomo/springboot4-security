package it.auth.jwt.provider;

import it.auth.jwt.token.BearerAuthenticationToken;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.List;

public class BearerAuthenticationProvider implements AuthenticationProvider {

    private static final String ROLES_CLAIM = "roles";
    private final JwtDecoder jwtDecoder;

    public BearerAuthenticationProvider(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        try {
            assert token != null;
            Jwt jwt = jwtDecoder.decode(token); // firma + exp/nbf + iss + aud
            List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);
            List<GrantedAuthority> authorities = (roles == null ? List.<String>of() : roles).stream()
                    .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                    .toList();
            BearerAuthenticationToken result = BearerAuthenticationToken.authenticated(jwt, authorities);
            result.setDetails(authentication.getDetails());
            return result;
        } catch (JwtException ex) {
            throw new BadCredentialsException("Invalid token", ex);
        }
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return BearerAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
