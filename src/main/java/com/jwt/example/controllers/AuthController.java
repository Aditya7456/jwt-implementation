package com.jwt.example.controllers;

import com.jwt.example.models.JwtRequest;
import com.jwt.example.models.JwtResponse;
import com.jwt.example.security.JwtHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
    /*
    private UserDetailsService userDetailsService;
    Used to:
        Load user from database using username (email).
        Spring Security uses this internally to fetch user data.

    private AuthenticationManager authenticationManager;
    🔥 VERY IMPORTANT.
        This is Spring Security’s authentication engine.
        It:
        Takes username + password
        Compares with DB
        Uses PasswordEncoder
        Throws exception if invalid
     */
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtHelper jwtHelper;

    // logger to log the info
    private final static Logger logger = LoggerFactory.getLogger(AuthController.class);

    // creating endpoints
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request){
        this.doAuthenticate(request.getEmail(),request.getPassword());
        //if we are here mean user is authenticated
        // load the userdetails from the database
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        // generating the token for user
        final String token = this.jwtHelper.generateToken(userDetails);
        //building the resposne
        JwtResponse jwtResponse = JwtResponse.builder()
                .jwtToken(token)
                .username(userDetails.getUsername()).build();

        return new ResponseEntity<>(jwtResponse,HttpStatus.OK);
    }
    // it will authenticate the user
    private void doAuthenticate(String email, String password) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email,password);
        try{
            authenticationManager.authenticate(authentication);
        } catch (AuthenticationException e) {
            throw new RuntimeException("Invalid username or Password !!");
        }
    }

}
