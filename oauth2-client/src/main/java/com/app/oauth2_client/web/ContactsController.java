package com.app.oauth2_client.web;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Controller
public class ContactsController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RestTemplate restTemplate = new RestTemplate();

    public ContactsController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/fetch-contacts")
    public String fetchResourceData(Model model, @AuthenticationPrincipal OAuth2User principal) {
        OAuth2AuthorizedClient client = getAuthorizedClient(principal.getName());

        ResponseEntity<List<String>> response = restTemplate.exchange(
                "http://localhost:8443/contacts",
                HttpMethod.GET,
                entity(client),
                new ParameterizedTypeReference<List<String>>() {
                }
        );
        model.addAttribute("contacts", response.getBody());
        return "page-templates";
    }

    private OAuth2AuthorizedClient getAuthorizedClient(String principalName) {
        return authorizedClientService.loadAuthorizedClient("confidential-client", principalName);
    }

    private HttpEntity<String> entity(OAuth2AuthorizedClient client) {
        String accessToken = client.getAccessToken().getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        return new HttpEntity<>(headers);
    }
}
