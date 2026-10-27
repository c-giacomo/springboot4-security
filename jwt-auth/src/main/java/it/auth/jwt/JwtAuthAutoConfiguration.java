package it.auth.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import it.auth.jwt.interfaces.JwtPrincipalResolver;
import it.auth.jwt.provider.BearerAuthenticationProvider;
import it.auth.jwt.provider.LoginAuthenticationProvider;
import it.auth.jwt.service.JwtTokenService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.List;
import java.util.Objects;

@AutoConfiguration
@ConditionalOnClass(AuthenticationManager.class)
@ConditionalOnProperty(prefix = "app.security.jwt", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(JwtProperties.class)
public class JwtAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    Clock jwtClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean
    JwtEncoder jwtEncoder(JwtProperties props) throws IOException {
        RSAPublicKey publicKey = readPublicKey(props.publicKey());
        RSAPrivateKey privateKey = readPrivateKey(props.privateKey());
        RSAKey jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(props.keyId())
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));
    }

    @Bean
    @ConditionalOnMissingBean
    JwtDecoder jwtDecoder(JwtProperties props) throws IOException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(readPublicKey(props.publicKey()))
                .signatureAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                .build();

        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.issuer()),   // exp + nbf (skew 60s) + iss
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        aud -> aud.contains(props.audience())));
        decoder.setJwtValidator(validator);
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean
    JwtTokenService jwtTokenService(JwtEncoder encoder, JwtProperties props, Clock jwtClock) {
        return new JwtTokenService(encoder, props, jwtClock);
    }

    @Bean
    @ConditionalOnMissingBean
    JwtPrincipalResolver jwtPrincipalResolver(UserDetailsService userDetailsService) {
        return jwt -> userDetailsService.loadUserByUsername(Objects.requireNonNull(jwt.getSubject()));
    }

    @Bean
    @ConditionalOnMissingBean(name = "jwtAuthenticationManager")
    AuthenticationManager jwtAuthenticationManager(UserDetailsService uds,
                                                   PasswordEncoder encoder,
                                                   JwtDecoder decoder,
                                                   JwtPrincipalResolver principalResolver) {
        return new ProviderManager(
                new LoginAuthenticationProvider(uds, encoder),
                new BearerAuthenticationProvider(decoder, principalResolver));
    }

    private static RSAPublicKey readPublicKey(Resource resource) throws IOException {
        try (InputStream in = resource.getInputStream()) {
            return RsaKeyConverters.x509().convert(in);
        }
    }

    private static RSAPrivateKey readPrivateKey(Resource resource) throws IOException {
        try (InputStream in = resource.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(in);
        }
    }
}
