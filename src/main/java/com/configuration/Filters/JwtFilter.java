package com.configuration.Filters;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.configuration.Service.DatabaseUserDetailsService;
import com.configuration.Service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//helps to create a bean in spring IOC container
@Component
public class JwtFilter extends OncePerRequestFilter{
	
	//autowiring the jwt service class to utilize the methods of jwt service class
	@Autowired
	JwtService jwtService;
	
	//using it to reduce the cyclic redundancy of userDetails
	@Autowired
	ApplicationContext appContext;
	
	@Override
	protected void doFilterInternal(
			HttpServletRequest request, 
			HttpServletResponse response, 
			FilterChain filterChain)
			throws ServletException, IOException {
		
		//getting the header from the request 
		/*
		 * sample request
		 * 
		 *  POST /api/resource HTTP/1.1
			Host: example.com
			Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
								  eyJzdWIiOiJ1c2VybmFtZSIsImlhdCI6MTYxN
								  jIzOTAyMiwiZXhwIjoxNjE2MjM5ODIyfQ
								  .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
			Content-Type: application/json
		
			{
		    	"data": "value"
			}

		 * */
		
		//getting the token part from the request which is having the Bearer
		final String authHeader = request.getHeader("Authorization");
		String username = null;
		String jwtToken = null;
		
		//verifying wether the token is valid or not
		if(authHeader != null && authHeader.startsWith("Bearer")) {
			//seperating the token with Bearer word
			jwtToken = authHeader.substring(7);
			//extracting the username from jwtToken
			username = jwtService.extractUsername(jwtToken);
		}
		
		
		//check if the username is valid or not and also verifying whether the request authenticated or not
		/*
		 * The SecurityContextHolder in Spring Security is a core part 
		 * of the framework responsible for storing security-related 
		 * details, primarily the authentication and user information 
		 * during the lifecycle of a request.
		 * */
		if(username != null && 
			SecurityContextHolder.getContext().getAuthentication() == null) {
			
			//load user details from database or any other source based on username
			UserDetails userDetails = appContext
					.getBean(DatabaseUserDetailsService.class)
					.loadUserByUsername(username);
			//validating the token if it is valid continue to the next filter
			if(jwtService.validateToken(jwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken upaToken = 
						new UsernamePasswordAuthenticationToken(
								userDetails,
								null,
								userDetails.getAuthorities()
								);
				//upaToken willnot have any data associated with the request so add request to it
				upaToken.setDetails(new WebAuthenticationDetails(request));
				
				//now we need to update the authentication as authenticated in securityHolder
				SecurityContextHolder.getContext().setAuthentication(upaToken);
			}
		}
		
		//once we are done there we need to move to next filter
		filterChain.doFilter(request, response);
		
		
	}

}
