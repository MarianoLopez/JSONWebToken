/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Security;


import com.jwt.jwt.Service.JWTService;
import com.jwt.jwt.Service.CustomAuthenticationProvider;
import java.io.UnsupportedEncodingException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 Here we have decided that everyone can access the / route, and that the /login route is only publicly available for POST requests. For all other routes, authentication is required. You may have noted that the JWTLoginFilter class and the JWTAuthenticationFilter class are missing. We will create them soon, but their goal is to filter for the /login route, and every other route, to decide what should happen when someone access these routes. In this class, we also added a default account that we can use to test our application.

The great thing here is that we have now secured our application without having to change code for existing routes. We did not alter our previously created UserController, nor did we have to write any xml-configuration.

The classes JWTLoginFilter and JWTAuthenticationFilter will handle logging in and authenticating users, respectively. Before we can use these classes, however, we need to create a class that can handle JWTs.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
    @Value("${jwt.EXPIRATIONTIME}")
    private String EXPIRATIONTIME;
    @Value("${jwt.SECRET}")
    private String SECRET;
    @Value("${jwt.TOKEN_PREFIX}")
    private String TOKEN_PREFIX;
    @Value("${jwt.HEADER_STRING}")
    private String HEADER_STRING;
   
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().
        sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .authorizeRequests()
            .antMatchers(HttpMethod.POST, "/login").permitAll().and()
            .authorizeRequests().antMatchers("/jwt/admin").hasAnyRole("ADMINISTRATOR").and()
            .authorizeRequests().antMatchers("/jwt/user").hasAnyRole("ADMINISTRATOR","USER").and()
            .addFilterBefore(jwtLoginFilter(),UsernamePasswordAuthenticationFilter.class)//filter the api/login requests
            .addFilterBefore(jwtAuthenticationFilter(),UsernamePasswordAuthenticationFilter.class);// And filter other requests to check the presence of JWT in header
    }
    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(userProvider());
    }
    
    @Bean 
    public CustomAuthenticationProvider userProvider(){return new CustomAuthenticationProvider();}
    @Bean
    public PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}
    @Bean
    public JWTAuthenticationFilter jwtAuthFilter(){return new JWTAuthenticationFilter();}
    @Bean
    public JWTService tokenAuth() throws IllegalArgumentException, UnsupportedEncodingException{return new JWTService(Long.parseLong(EXPIRATIONTIME),SECRET,TOKEN_PREFIX,HEADER_STRING);}
    @Bean
    public JWTLoginFilter jwtLoginFilter() throws Exception{return new JWTLoginFilter("/login", authenticationManager());}
    @Bean
    public JWTAuthenticationFilter jwtAuthenticationFilter(){return new JWTAuthenticationFilter();}
 
}