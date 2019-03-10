package com.okta.developer.gateway.security.oauth2;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

import java.util.Optional;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

public class AuthHeaderFilter extends ZuulFilter {

    private final AuthorizationHeaderUtil headerUtil;

    public AuthHeaderFilter(AuthorizationHeaderUtil headerUtil) {
        this.headerUtil = headerUtil;
    }

    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        Optional<String> authorizationHeader = headerUtil.getAuthorizationHeaderFromOAuth2Context();
        System.out.println("======================================================");
        System.out.println("Authorization Header: " + authorizationHeader.get());
        authorizationHeader.ifPresent(s -> ctx.addZuulRequestHeader("Authorization", s));
        return null;
    }
}
