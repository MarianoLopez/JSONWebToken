/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Security;

import com.jwt.jwt.Service.JWTService;
import com.jwt.jwt.Model.AccountCredentials;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import org.springframework.beans.factory.annotation.Autowired;

/**
We now have everything set up to use JWTs in our authentication process. We'll first take a look at the JWTLoginFilter class. This class will intercept POST requests on the /login path and attempt to authenticate the user. When the user is successfully authenticated, it will return a JWT in the Authorization header of the response
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {
  @Autowired
  private JWTService tokenAuth;
  
  public JWTLoginFilter(String url, AuthenticationManager authManager) {
    super(new AntPathRequestMatcher(url));
    setAuthenticationManager(authManager); 
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {
    //System.out.println("JWTLoginFilter - attemptAuthentication");
    AccountCredentials creds = new ObjectMapper().readValue(req.getInputStream(), AccountCredentials.class);//no permite inner class
    return getAuthenticationManager().authenticate(
        new UsernamePasswordAuthenticationToken(
            creds.getUsername(),
            creds.getPassword(),
            Collections.emptyList()
        )
    );     
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest req,HttpServletResponse res, FilterChain chain,Authentication auth) throws IOException, ServletException {
      //System.out.println("JWTLoginFilter - successfullAuth");
      tokenAuth.addAuthentication(res, auth.getName());
  } 
}
