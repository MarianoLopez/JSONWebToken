/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Service;

import com.jwt.jwt.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 *
 * @author 36194445
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider{
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserService userService;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();
        if(name!=null&&password!=null){
            UserDetails u = userService.loadUserByUsername(name);
            if(u!=null&&u.getUsername().equals(name)&&//remover OR al utilizar solo cryp
                    (passwordEncoder.matches(password, u.getPassword())||password.equals(u.getPassword()))){
                return new UsernamePasswordAuthenticationToken(name, password, u.getAuthorities());  
            }else{
                System.out.println("CustomAuthenticationProvider bad credentials");
                throw new AuthenticationException("bad credentials") {};
            }
        }else{
            System.out.println("CustomAuthenticationProvider user not found");
            throw new AuthenticationException("user not found") {};
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
    
}