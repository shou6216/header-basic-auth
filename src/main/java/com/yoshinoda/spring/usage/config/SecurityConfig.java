package com.yoshinoda.spring.usage.config;

import com.yoshinoda.spring.usage.security.HeaderAccessDeniedHandler;
import com.yoshinoda.spring.usage.security.HeaderAuthenticationEntryPoint;
import com.yoshinoda.spring.usage.security.service.HeaderUserDetailsService;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated().and()
            .formLogin()
                .loginPage("/login").permitAll()
                .loginProcessingUrl("/authentication")
                .and()
            .csrf().disable()
            .exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
                "/*.ico"
                );
    }

    AuthenticationEntryPoint authenticationEntryPoint() {
        return new HeaderAuthenticationEntryPoint();
    }

    AccessDeniedHandler accessDeniedHandler() {
        return new HeaderAccessDeniedHandler();
    }

    RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() throws Exception {
        RequestHeaderAuthenticationFilter filter = new RequestHeaderAuthenticationFilter();
        //filter.setContinueFilterChainOnUnsuccessfulAuthentication(true);
        //filter.setCredentialsRequestHeader("hoge");
        filter.setPrincipalRequestHeader("Authentication");
        //filter.setExceptionIfHeaderMissing(false);
        filter.setAuthenticationManager(authenticationManager());
        //filter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login"));
        return filter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(preAuthenticationProvider());
    }

    PreAuthenticatedAuthenticationProvider preAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(new HeaderUserDetailsService());
        return provider;
    }
}
