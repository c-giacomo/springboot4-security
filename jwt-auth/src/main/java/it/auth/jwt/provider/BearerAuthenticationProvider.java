package it.auth.jwt.provider;

import it.auth.jwt.interfaces.JwtPrincipalResolver;
import it.auth.jwt.token.BearerAuthenticationToken;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

public class BearerAuthenticationProvider implements AuthenticationProvider {

    private final JwtDecoder jwtDecoder;
    private final JwtPrincipalResolver principalResolver;
    private final UserDetailsChecker statusChecker = new AccountStatusUserDetailsChecker();

    public BearerAuthenticationProvider(JwtDecoder jwtDecoder, JwtPrincipalResolver principalResolver) {
        this.jwtDecoder = jwtDecoder;
        this.principalResolver = principalResolver;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = (String) authentication.getCredentials();
        assert token != null;

        Jwt jwt;
        try {
            jwt = jwtDecoder.decode(token);   // firma + exp/nbf + iss + aud
        } catch (JwtException ex) {
            throw new BadCredentialsException("Invalid token", ex);
        }

        UserDetails user;
        try {
            user = principalResolver.resolve(jwt);
        } catch (UsernameNotFoundException ex) {
            throw new BadCredentialsException("Invalid token", ex);   // utente cancellato dopo l'emissione
        }
        statusChecker.check(user);   // disabilitato / bloccato / scaduto -> 401 subito

        BearerAuthenticationToken result = BearerAuthenticationToken.authenticated(user, jwt);
        result.setDetails(authentication.getDetails());
        return result;

    }

    @Override
    public boolean supports(@NonNull Class<?> authentication) {
        return BearerAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
