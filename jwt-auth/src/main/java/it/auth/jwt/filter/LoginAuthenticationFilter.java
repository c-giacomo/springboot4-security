package it.auth.jwt.filter;

import it.auth.jwt.token.LoginAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

public class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public record LoginRequest(String username, String password) {}

    private final JsonMapper jsonMapper;

    public LoginAuthenticationFilter(AuthenticationManager authenticationManager,
                                     JsonMapper jsonMapper,
                                     AuthenticationSuccessHandler successHandler,
                                     AuthenticationFailureHandler failureHandler) {
        super(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/auth/login"), authenticationManager);
        this.jsonMapper = jsonMapper;
        setAuthenticationSuccessHandler(successHandler);
        setAuthenticationFailureHandler(failureHandler);
        setSecurityContextRepository(new RequestAttributeSecurityContextRepository()); // niente HttpSession
        setAllowSessionCreation(false);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        LoginRequest body;
        try {
            body = jsonMapper.readValue(request.getInputStream(), LoginRequest.class);
        } catch (IOException | JacksonException ex) {
            throw new BadCredentialsException("Malformed login request");
        }
        if (body == null || !StringUtils.hasText(body.username()) || !StringUtils.hasText(body.password())) {
            throw new BadCredentialsException("Malformed login request");
        }
        LoginAuthenticationToken authRequest = LoginAuthenticationToken.unauthenticated(body.username().trim(), body.password());
        authRequest.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return getAuthenticationManager().authenticate(authRequest);
    }
}
