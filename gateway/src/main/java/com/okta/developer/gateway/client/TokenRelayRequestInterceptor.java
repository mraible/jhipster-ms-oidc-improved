package com.okta.developer.gateway.client;

import com.okta.developer.gateway.security.oauth2.AuthorizationHeaderUtil;

import feign.RequestInterceptor;
import feign.RequestTemplate;

import java.util.Optional;

public class TokenRelayRequestInterceptor implements RequestInterceptor {

    private static final String AUTHORIZATION = "Authorization";

    private final AuthorizationHeaderUtil authorizationHeaderUtil;

    TokenRelayRequestInterceptor(AuthorizationHeaderUtil authorizationHeaderUtil) {
        super();
        this.authorizationHeaderUtil = authorizationHeaderUtil;
    }

    @Override
    public void apply(RequestTemplate template) {
        Optional<String> authorizationHeader = authorizationHeaderUtil.getAuthorizationHeaderFromOAuth2Context();
        authorizationHeader.ifPresent(s -> template.header(AUTHORIZATION, s));
    }
}
