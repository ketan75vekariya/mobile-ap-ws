package com.appsdeveloperblog.app.ws.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthorizationFilter extends BasicAuthenticationFilter{
	
	private final SecretKey signingKey;
	
	

	
	public AuthorizationFilter(AuthenticationManager authManager,AppProperties appProperties) {
		super(authManager);
		this.signingKey = Keys.hmacShaKeyFor(
				appProperties.getTokenSecret().getBytes(StandardCharsets.UTF_8)
        );
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest req,
			HttpServletResponse res,
			FilterChain chain) throws IOException, ServletException{
		
		String header = req.getHeader(SecurityConstants.HEADER_STRING);
		
		if(header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			chain.doFilter(req, res);
			return;
		}
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(SecurityConstants.HEADER_STRING);
		
		if(token != null) {
			token = token.replace(SecurityConstants.TOKEN_PREFIX, "");
			
			Claims claims = Jwts.parser()               // in 0.13.0 returns JwtParserBuilder
	                .verifyWith(signingKey)             // SecretKey, correct overload
	                .build()
	                .parseSignedClaims(token)           // replaces parseClaimsJws(...)
	                .getPayload();                      // replaces getBody()

	        String user = claims.getSubject();

			if(user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
			}
		}
		
		return null;
	}
	

}
