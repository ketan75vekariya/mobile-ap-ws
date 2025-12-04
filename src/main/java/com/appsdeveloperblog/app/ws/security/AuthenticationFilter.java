package com.appsdeveloperblog.app.ws.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Date;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.appsdeveloperblog.app.ws.SpringApplicationContext;
import com.appsdeveloperblog.app.ws.service.UserService;
import com.appsdeveloperblog.app.ws.shared.dto.UserDto;
import com.appsdeveloperblog.app.ws.ui.model.request.UserLoginRequestModel;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final Key signingKey;
    

    public AuthenticationFilter(AuthenticationManager authenticationManager,AppProperties appProperties) {
        this.authenticationManager = authenticationManager;

        //If TOKEN_SECRET is plain text instead, use this line instead of the two above:
         this.signingKey = Keys.hmacShaKeyFor(appProperties.getTokenSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            UserLoginRequestModel creds = new ObjectMapper()
                    .readValue(req.getInputStream(), UserLoginRequestModel.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            creds.getEmail(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth)
            throws IOException, ServletException {

        String userName = ((User) auth.getPrincipal()).getUsername();

        String token = Jwts.builder()
                .subject(userName)   // replaces setSubject(...)
                .expiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME)) // replaces setExpiration(...)
                // new signWith signature; SignatureAlgorithm enum is deprecated
                .signWith(signingKey)
                .compact();
        UserService userService = (UserService)SpringApplicationContext.getBean("userServiceImpl");
        UserDto userDto = userService.getUser(userName);

        res.addHeader(SecurityConstants.HEADER_STRING,
                SecurityConstants.TOKEN_PREFIX + token);
        res.addHeader("UserID", userDto.getUserId());
    }
}
