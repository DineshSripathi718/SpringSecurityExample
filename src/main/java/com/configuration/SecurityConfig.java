package com.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.configuration.Filters.JwtFilter;
import com.configuration.Service.DatabaseUserDetailsService;

@Configuration
@EnableWebSecurity

public class SecurityConfig{
	
	//now spring will assign the object of DatabaseUserDetailsService here
	@Autowired
	DatabaseUserDetailsService userDetailsService;	
	
	@Autowired
	JwtFilter jwtFilter;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
		
		return httpSecurity.csrf(customizer -> customizer.disable())
		.authorizeHttpRequests(
				request -> request.requestMatchers("/register", "/loginUser", "/homepage")
									.permitAll()
								  .anyRequest().authenticated()
				)
		.oauth2Login(Customizer.withDefaults())
		.formLogin(Customizer.withDefaults())
		.httpBasic(Customizer.withDefaults())
		.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
		.build();
	}
	
	@Bean
	public AuthenticationProvider getAuthentication() {
		DaoAuthenticationProvider daoAuthentication = new DaoAuthenticationProvider();
		
		//not encoding the password which used in the eariler stage
		//daoAuthentication.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		
		//daoAuthentication which using the BCryptPasswordEncoding
		System.out.println(userDetailsService.toString());
		daoAuthentication.setUserDetailsService(userDetailsService);
		daoAuthentication.setPasswordEncoder(new BCryptPasswordEncoder(12));
		
		
		return daoAuthentication;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
		return authConfiguration.getAuthenticationManager();
	}

	
//	@Bean
//	public UserDetailsService userDetails() {
//		
//		UserDetails user1 = User.withDefaultPasswordEncoder()
//								.username("Ravi")
//								.password("ravi")
//								.roles("admin", "trainer").build();
//		
//		return new InMemoryUserDetailsManager(user1);
//	}
}
