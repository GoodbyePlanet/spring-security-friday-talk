package com.app.oauth2_client.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ForwardedHeaderUtils;
import org.springframework.web.util.UriComponents;

import java.io.IOException;
import java.net.URI;

/**
 *  * This filter ensures that the loopback IP <code>127.0.0.1</code> is used to access the
 *  * client application so that the sample works correctly, due to the fact that redirect URIs with
 *  * "localhost" are rejected by the Spring Authorization Server, because the OAuth 2.1
 *  * draft specification states:
 *  *
 *  * <pre>
 *  *     While redirect URIs using localhost (i.e.,
 *  *     "http://localhost:{port}/{path}") function similarly to loopback IP
 *  *     redirects described in Section 10.3.3, the use of "localhost" is NOT
 *  *     RECOMMENDED.
 *  * </pre>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoopBackIpRedirectFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getServerName().equals("localhost") && request.getHeader("host") != null) {
            HttpHeaders headers = new ServletServerHttpRequest(request).getHeaders();
            String fullUrl = request.getRequestURL().toString();

            if (request.getQueryString() != null) {
                fullUrl += "?" + request.getQueryString();
            }

            UriComponents uriComponents = ForwardedHeaderUtils.adaptFromForwardedHeaders(URI.create(fullUrl), headers)
                    .host("127.0.0.1")
                    .build();
            response.sendRedirect(uriComponents.toUriString());
            return;
        }
        filterChain.doFilter(request, response);
    }

}
