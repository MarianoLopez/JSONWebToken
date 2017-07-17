/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.jwt.jwt.Controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;



@RestController
@RequestMapping("/jwt")
public class Controller {
 
    @RequestMapping(value ="/admin",method = RequestMethod.GET)
    public String admin(){
        return "ADMIN";
    }

    @RequestMapping(value ="/user", method = RequestMethod.GET)
    public String user(){
        return "USER";
    }
}
