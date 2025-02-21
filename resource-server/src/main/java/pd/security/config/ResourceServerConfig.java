package pd.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/contacts/**")
                .authorizeHttpRequests(authorize -> {
                            authorize.requestMatchers("/contacts/**").hasAuthority("SCOPE_contacts.read");
                            authorize.anyRequest().authenticated();
                        })
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(withDefaults()));
        return http.build();
    }
}
