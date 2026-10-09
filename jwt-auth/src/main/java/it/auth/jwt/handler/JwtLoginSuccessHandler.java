package it.auth.jwt.handler;

import it.auth.jwt.service.JwtTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;

public class JwtLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenService tokenService;
    private final JsonMapper jsonMapper;

    public JwtLoginSuccessHandler(JwtTokenService tokenService, JsonMapper jsonMapper) {
        this.tokenService = tokenService;
        this.jsonMapper = jsonMapper;
    }

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request, HttpServletResponse response,
                                        @NonNull Authentication authentication) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        jsonMapper.writeValue(response.getOutputStream(), tokenService.issue(authentication));
    }
}
