package it.auth.jwt.filter;

import it.auth.jwt.token.BearerAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BearerAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Pattern BEARER = Pattern.compile("^Bearer\\s+(\\S+)$", Pattern.CASE_INSENSITIVE);

    public BearerAuthenticationFilter(AuthenticationManager authenticationManager,
                                      AuthenticationFailureHandler failureHandler) {
        // Si attiva solo se c'è un header Authorization: Bearer ...
        super(request -> {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            return header != null && BEARER.matcher(header).matches();
        }, authenticationManager);
        setAuthenticationFailureHandler(failureHandler);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        Matcher m = BEARER.matcher(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (!m.matches()) {
            throw new BadCredentialsException("Invalid Authorization header");
        }
        BearerAuthenticationToken authRequest = BearerAuthenticationToken.unauthenticated(m.group(1));
        authRequest.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return getAuthenticationManager().authenticate(authRequest);
    }

    /** Diversamente dal login, qui NON si risponde: si imposta il contesto e si prosegue la catena. */
    @Override
    protected void successfulAuthentication(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                            FilterChain chain, @NonNull Authentication authResult)
            throws IOException, ServletException {
        SecurityContextHolderStrategy strategy = SecurityContextHolder.getContextHolderStrategy();
        SecurityContext context = strategy.createEmptyContext();
        context.setAuthentication(authResult);
        strategy.setContext(context);
        chain.doFilter(request, response);
    }
}
