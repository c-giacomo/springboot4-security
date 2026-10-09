package it.auth.jwt;

import it.auth.jwt.filter.BearerAuthenticationFilter;
import it.auth.jwt.filter.LoginAuthenticationFilter;
import it.auth.jwt.handler.JwtLoginSuccessHandler;
import it.auth.jwt.handler.RestAuthenticationEntryPoint;
import it.auth.jwt.service.JwtTokenService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tools.jackson.databind.json.JsonMapper;

public class JwtAuthConfigurer extends AbstractHttpConfigurer<JwtAuthConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable);
    }

    @Override
    public void configure(HttpSecurity http) {
        ApplicationContext ctx = http.getSharedObject(ApplicationContext.class);
        AuthenticationManager am = ctx.getBean("jwtAuthenticationManager", AuthenticationManager.class);
        JsonMapper mapper = ctx.getBean(JsonMapper.class);
        JwtTokenService tokenService = ctx.getBean(JwtTokenService.class);

        var entryPoint = new RestAuthenticationEntryPoint(mapper);
        var failureHandler = new AuthenticationEntryPointFailureHandler(entryPoint);

        // Istanziati qui, mai come @Bean
        http.exceptionHandling(e -> e.authenticationEntryPoint(entryPoint));
        http.addFilterBefore(
                new LoginAuthenticationFilter(am, mapper,
                        new JwtLoginSuccessHandler(tokenService, mapper), failureHandler),
                UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(
                new BearerAuthenticationFilter(am, failureHandler),
                UsernamePasswordAuthenticationFilter.class);
    }

    public static JwtAuthConfigurer jwtAuth() {
        return new JwtAuthConfigurer();
    }
}
