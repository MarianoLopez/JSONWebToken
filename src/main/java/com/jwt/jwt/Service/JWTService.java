/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.UnsupportedEncodingException;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
    Our JWT service will deal with the creation and verification of our tokens. In this example, we will create a token based on a username and an expiration time, and then sign it with a secret (using an HMAC). We will use io.jsonwebtoken.Jwts here for creating and verifying our tokens; they also provide a bunch of algorithms we can use to sign our secret.
 */

public class JWTService {
    private long EXPIRATIONTIME;
    //private String SECRET;
    private String TOKEN_PREFIX;
    private String HEADER_STRING;
    private Algorithm algorithm;
    @Autowired
    private UserDetailsService userDetails;
    

    public JWTService(long EXPIRATIONTIME,String SECRET, String TOKEN_PREFIX, String HEADER_STRING) throws IllegalArgumentException, UnsupportedEncodingException {
        //this.setSECRET(SECRET);
        this.setEXPIRATIONTIME(EXPIRATIONTIME);
        this.setTOKEN_PREFIX(TOKEN_PREFIX);
        this.setHEADER_STRING(HEADER_STRING);
        this.setAlgorithm(Algorithm.HMAC512(SECRET));
    } 
    
    public void addAuthentication(HttpServletResponse res, String username) {
        //System.out.println("TokenAuthenticationService addAuth");
        try {
            String token = JWT.create()
                .withSubject(username)
                .withIssuer("MEC")
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .sign(algorithm);
            res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + token);
        } catch (JWTCreationException exception){
            System.out.println("JWTCreationException "+exception.toString());
            throw new JWTCreationException(exception.toString(), exception.getCause());
        }
    }

    public Authentication getAuthentication(HttpServletRequest request){
      //System.out.println("TokenAuthenticationService getAuth");
      String token = request.getHeader(HEADER_STRING);
      if (token != null) {
        try {
            JWTVerifier verifier = JWT.require(algorithm).withIssuer("MEC").build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token.replace(TOKEN_PREFIX, "").trim());
            try{
                UserDetails u = this.getUserDetails().loadUserByUsername(jwt.getSubject());
                return jwt.getSubject() != null ? new UsernamePasswordAuthenticationToken(u.getName(), u.getPassword(),u.getAuthorities()):null;
            }catch(UsernameNotFoundException e){
                System.out.println("TokenAuth Username not found - null");
                throw new UsernameNotFoundException("Username not found");
            }
        } catch (JWTVerificationException exception){
            System.out.println("JWTVerificationException "+exception.toString());
            throw new JWTVerificationException(exception.toString());
        }
      }
      return null;
    }
    
    
     public long getEXPIRATIONTIME() {
        return EXPIRATIONTIME;
    }

    private void setEXPIRATIONTIME(long EXPIRATIONTIME) {
        this.EXPIRATIONTIME = EXPIRATIONTIME;
    }

    /*public String getSECRET() {
        return SECRET;
    }

    private void setSECRET(String SECRET) {
        this.SECRET = SECRET;
    }*/

    public String getTOKEN_PREFIX() {
        return TOKEN_PREFIX;
    }

    private void setTOKEN_PREFIX(String TOKEN_PREFIX) {
        this.TOKEN_PREFIX = TOKEN_PREFIX;
    }

    public String getHEADER_STRING() {
        return HEADER_STRING;
    }

    private void setHEADER_STRING(String HEADER_STRING) {
        this.HEADER_STRING = HEADER_STRING;
    }
    
    public UserDetailsService getUserDetails() {
        return userDetails;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public final void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }
    
    

   
}
