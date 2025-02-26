package com.app.oauth2_client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   ClientRegistrationRepository registrationRepository) throws Exception {
        httpSecurity.authorizeHttpRequests((authorize) ->
                        authorize.requestMatchers("/logged-out").permitAll()
                                .anyRequest().authenticated())
                .oauth2Login(Customizer.withDefaults())
                .logout(logout ->
                        logout.logoutSuccessHandler(oidcLogoutSuccessHandler(registrationRepository)));

        return httpSecurity.build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

        // Set the location that the End-User's User Agent will be redirected to
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8080/logged-out");

        return oidcLogoutSuccessHandler;
    }
}
