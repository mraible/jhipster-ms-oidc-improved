package com.okta.developer.gateway.config;

import com.okta.developer.gateway.security.AuthoritiesConstants;
import com.okta.developer.gateway.security.oauth2.AuthorizationHeaderFilter;
import com.okta.developer.gateway.security.oauth2.AuthorizationHeaderUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CorsFilter;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    public SecurityConfiguration(CorsFilter corsFilter) {
        this.corsFilter = corsFilter;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
            .antMatchers(HttpMethod.OPTIONS, "/**")
            .antMatchers("/app/**/*.{js,html}")
            .antMatchers("/i18n/**")
            .antMatchers("/content/**")
            .antMatchers("/swagger-ui/index.html")
            .antMatchers("/test/**")
            .antMatchers("/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and()
            .addFilterBefore(corsFilter, CsrfFilter.class)
            .headers()
            .frameOptions()
            .disable()
        .and()
            .authorizeRequests()
            .antMatchers("/api/**").authenticated()
            .antMatchers("/authorize").authenticated()
            .antMatchers("/management/health").permitAll()
            .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .anyRequest().permitAll()
        .and()
            .oauth2Login();
    }

    @Bean
    @SuppressWarnings("unchecked")
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();
                Collection<String> groups = (Collection<String>) userInfo.getClaims().get("groups");
                if (groups == null) {
                    groups = (Collection<String>) userInfo.getClaims().get("roles");
                }
                mappedAuthorities.addAll(groups.stream()
                    .filter(group -> group.startsWith("ROLE_"))
                    .map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            });

            return mappedAuthorities;
        };
    }

    @Bean
    public AuthorizationHeaderFilter authHeaderFilter(AuthorizationHeaderUtil headerUtil) {
        return new AuthorizationHeaderFilter(headerUtil);
    }
}
