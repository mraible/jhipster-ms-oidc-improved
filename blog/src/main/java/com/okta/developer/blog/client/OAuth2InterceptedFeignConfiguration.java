package com.okta.developer.blog.client;

import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;

import java.io.IOException;

public class OAuth2InterceptedFeignConfiguration {

    @Bean(name = "oauth2RequestInterceptor")
    public RequestInterceptor getOAuth2RequestInterceptor(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) throws IOException {
        return new TokenRelayRequestInterceptor(authorizedClient);
    }
}
