/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Service;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 *
 * @author MarianoLopez
 */
@Service
public class UserService implements UserDetailsService{
     public List<UserDetails> getAll(){
        List<UserDetails> users = new ArrayList<>();
        users.add(new org.springframework.security.core.userdetails.User("Mariano", "$2a$10$XZGE/sbVasUtIcmT/9jMQ.4u/AxboZljS7MVQF3.z0DOepqw.7Lau",//dni
               Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));
        users.add(new org.springframework.security.core.userdetails.User("Admin", "admin",
               Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMINISTRATOR"),new SimpleGrantedAuthority("ROLE_USER"))));
        return users;
    }
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username!=null&&username.length()>0){
                UserDetails u = null;
                for (UserDetails user : getAll()) {
                    if(user.getUsername().equals(username)){
                        u = user;
                    }
                }
                if(u==null){
                    System.out.println("UserSerive Username not found - null");
                    throw new UsernameNotFoundException("Username not found");
                }else{
                    //return Usuario Spring (username,pass,estado(bool),accountnonexpired,credentialsnonexpired,accountnonlocked,roles)
                    return new org.springframework.security.core.userdetails.User(u.getName(), u.getPassword(),u.getAuthorities());
                }
        }else{
             System.out.println("UserSerive Username not found - null");
             throw new UsernameNotFoundException("Username not found");
        }
    }   
}
