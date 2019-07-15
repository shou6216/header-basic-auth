package com.yoshinoda.spring.usage.config;

import com.yoshinoda.spring.usage.security.HeaderAccessDeniedHandler;
import com.yoshinoda.spring.usage.security.HeaderAuthenticationSuccessHandler;
import com.yoshinoda.spring.usage.security.TokenFilter;
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
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.filter.GenericFilterBean;

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
                .loginProcessingUrl("/login").permitAll()
                        .usernameParameter("userId")
                        .passwordParameter("pwd")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
                .and()
            .csrf().disable()
            .addFilterBefore(tokenFilter(), UsernamePasswordAuthenticationFilter.class)
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
        return new LoginUrlAuthenticationEntryPoint("/login");
    }

    AccessDeniedHandler accessDeniedHandler() {
        return new HeaderAccessDeniedHandler();
    }

    AuthenticationSuccessHandler authenticationSuccessHandler() {
        //TODO 認証失敗した場合の挙動。エラー画面に飛ぶ
        return new HeaderAuthenticationSuccessHandler();
    }

    AuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler("/login?error");
    }

    LogoutSuccessHandler logoutSuccessHandler() {
        return new SimpleUrlLogoutSuccessHandler();
    }

    GenericFilterBean tokenFilter() throws Exception {
        return new TokenFilter();
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(preAuthenticationProvider());
//    }

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

//    PreAuthenticatedAuthenticationProvider preAuthenticationProvider() {
//        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
//        //provider.setPreAuthenticatedUserDetailsService(new HeaderUserDetailsService());
//        return provider;
//    }
}
