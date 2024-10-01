package com.pd.spring_security_friday_talk.config;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
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
import io.jsonwebtoken.io.Decoders;
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

        Jwt jwt = getJwt(token);
        String username = jwt.getClaimAsString(JwtClaimNames.SUB);
        Collection<GrantedAuthority> authorities = GRANTED_AUTHORITIES_CONVERTER.convert(jwt);
        var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return null;
    }

    private Jwt getJwt(String token) {
        try {
            byte[] bytes = Base64.getDecoder().decode(jwtSecret.getBytes());
            SecretKey secret = new SecretKeySpec(bytes, "SHA256");
            Claims payload = Jwts.parser().verifyWith(secret).build().parseSignedClaims(token).getPayload();

            return Jwt.withTokenValue(token).claims(claims -> claims.putAll(payload)).build();
        } catch (JwtException exception) {
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, exception.getMessage(), null), exception, null);
        }
    }
}
