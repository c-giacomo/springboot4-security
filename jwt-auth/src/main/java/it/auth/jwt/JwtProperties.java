package it.auth.jwt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(
        @NotBlank
        String issuer,
        @NotBlank
        String audience,
        @NotBlank
        String keyId,
        @NotNull
        Duration accessTokenTtl,
        @NotNull
        Resource privateKey,
        @NotNull
        Resource publicKey) { }
