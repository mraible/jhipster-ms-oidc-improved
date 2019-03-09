package com.okta.developer.blog.client;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;

public class TokenRelayRequestInterceptor implements RequestInterceptor {

    private static final String AUTHORIZATION = "Authorization";
    private final OAuth2AuthorizedClient authorizedClient;

    TokenRelayRequestInterceptor(OAuth2AuthorizedClient authorizedClient) {
        super();
        this.authorizedClient = authorizedClient;
    }

    @Override
    public void apply(RequestTemplate template) {
        String authorizationHeader = authorizedClient.getAccessToken().getTokenType() + " " + authorizedClient.getAccessToken().getTokenValue();
        template.header(AUTHORIZATION, authorizationHeader);
    }
}
