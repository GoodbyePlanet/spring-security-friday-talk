package com.pd.spring_security_friday_talk.config;

import java.util.Collection;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AuthorizationRequestConverter implements AuthenticationConverter {

    private static final DefaultBearerTokenResolver BEARER_TOKEN_RESOLVER =
        new DefaultBearerTokenResolver();

    private static final JwtGrantedAuthoritiesConverter GRANTED_AUTHORITIES_CONVERTER =
        new JwtGrantedAuthoritiesConverter();

    private final String jwtSecret;

    @Override
    public Authentication convert(HttpServletRequest request) {
        String token = BEARER_TOKEN_RESOLVER.resolve(request);

        if (token == null) {
            return null;
        }

        Jwt jwt = extractAndDecodeHeader(token);
        String username = jwt.getClaimAsString(JwtClaimNames.SUB);
        Collection<GrantedAuthority> authorities = GRANTED_AUTHORITIES_CONVERTER.convert(jwt);
        SecurityContextHolder
            .getContext()
            .setAuthentication(new UsernamePasswordAuthenticationToken(username, null, authorities));

        return null;
    }

    private Jwt extractAndDecodeHeader(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
            Claims payload = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();

            return Jwt.withTokenValue(token)
                .claims(claims -> claims.putAll(payload))
                .headers(headers -> {
                    headers.put("alg", "HS256");
                    headers.put("typ", "JWT");
                }).build();
        } catch (JwtException exception) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, exception.getMessage(), null), exception, null);
        }
    }
}
