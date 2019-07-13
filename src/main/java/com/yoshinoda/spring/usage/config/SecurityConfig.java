package com.yoshinoda.spring.usage.config;

import com.yoshinoda.spring.usage.security.HeaderAccessDeniedHandler;
import com.yoshinoda.spring.usage.security.HeaderAuthenticationEntryPoint;
import com.yoshinoda.spring.usage.security.HeaderAuthenticationFailureHandler;
import com.yoshinoda.spring.usage.security.HeaderAuthenticationSuccessHandler;
import com.yoshinoda.spring.usage.security.service.HeaderUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login").permitAll()
                .loginProcessingUrl("/authentication")
                        .usernameParameter("userId")
                        .passwordParameter("pwd")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
                .addLogoutHandler(new CookieClearingLogoutHandler())
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

    AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new HeaderAuthenticationSuccessHandler();
    }

    AuthenticationFailureHandler authenticationFailureHandler() {
        return new HeaderAuthenticationFailureHandler();
    }

    LogoutSuccessHandler logoutSuccessHandler() {
        return new HttpStatusReturningLogoutSuccessHandler();
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

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth,
                                HeaderUserDetailsService userDetailsService,
                                PasswordEncoder passwordEncoder) throws Exception {

        auth.eraseCredentials(true)
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);

    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    PreAuthenticatedAuthenticationProvider preAuthenticationProvider() {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        //provider.setPreAuthenticatedUserDetailsService(new HeaderUserDetailsService());
        return provider;
    }
}
