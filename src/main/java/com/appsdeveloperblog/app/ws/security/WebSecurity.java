package com.appsdeveloperblog.app.ws.security;

import com.appsdeveloperblog.app.ws.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurity {

    private final UserService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public WebSecurity(UserService userDetailsService,
                       BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, AppProperties appProperties)
            throws Exception {
    	
    	//AuthenticationFilter authFilter = new AuthenticationFilter(authenticationManager);

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, SecurityConstants.SIGH_UP_URL).permitAll()
                .anyRequest().authenticated()
            )
     // add custom authentication filter at the appropriate place
        .addFilterBefore(getAuthenticationFilter(authenticationManager,appProperties), UsernamePasswordAuthenticationFilter.class)
        .addFilter(new AuthorizationFilter(authenticationManager,appProperties))
        .sessionManagement(session -> 
        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder authBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authBuilder
            .userDetailsService(userDetailsService)
            .passwordEncoder(bCryptPasswordEncoder);

        return authBuilder.build();
    }
    
    public AuthenticationFilter getAuthenticationFilter(AuthenticationManager authenticationManager, AppProperties appProperties) throws Exception{
    	final AuthenticationFilter filter = new AuthenticationFilter(authenticationManager, appProperties);
    	filter.setFilterProcessesUrl("/users/login");
    	return filter;
    }
}
