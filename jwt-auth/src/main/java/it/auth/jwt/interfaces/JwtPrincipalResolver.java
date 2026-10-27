package it.auth.jwt.interfaces;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;

@FunctionalInterface
public interface JwtPrincipalResolver {
    /** Dato un JWT già validato, restituisce il principal da mettere nel SecurityContext. */
    UserDetails resolve(Jwt jwt) throws UsernameNotFoundException;
}
