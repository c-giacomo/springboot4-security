package it.auth.jwt.service;

import it.auth.jwt.JwtProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public class JwtTokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties props;
    private final Clock clock;

    public JwtTokenService(JwtEncoder jwtEncoder, JwtProperties props, Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.props = props;
        this.clock = clock;
    }

    public TokenResponse issue(Authentication authentication) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(props.accessTokenTtl());

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .audience(List.of(props.audience()))
                .subject(authentication.getName())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())   // jti: utile per eventuale revoca
                .claim("roles", roles)              // niente dati sensibili nel payload!
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(props.keyId())
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenResponse(token, "Bearer", props.accessTokenTtl().toSeconds());
    }
}
