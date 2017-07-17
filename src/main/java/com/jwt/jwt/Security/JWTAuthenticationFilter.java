/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Security;

import com.jwt.jwt.Service.JWTService;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.GenericFilterBean;

/**
During the authentication attempt, which is dealt by the attemptAuthentication method, we retrieve the username and password from the request. After they are retrieved, we use the AuthenticationManager to verify that these details match with an existing user. If it does, we enter the successfulAuthentication method. In this method we fetch the name from the authenticated user, and pass it on to TokenAuthenticationService, which will then add a JWT to the response.
 */
public class JWTAuthenticationFilter extends GenericFilterBean {
   @Autowired
   private JWTService tokenService;
   
    
  @Override
  public void doFilter(ServletRequest request,ServletResponse response,FilterChain filterChain)throws IOException, ServletException {
    //System.out.println("JWTAuthenticationFilter doFilter");
    HttpServletRequest res = (HttpServletRequest)request;
    Authentication authentication = tokenService.getAuthentication(res);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    filterChain.doFilter(request,response);
  }   
}
