package com.jwt.example.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private JwtHelper jwtHelper;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        if (request.getServletPath().equals("/auth/login")) {
//            filterChain.doFilter(request, response);
//            return;
//        }

        //Authorization
        // extracted the authorization header
        String requestHeader = request.getHeader("Authorization");
        // example Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...

        // Print header for debugging.
        logger.info("Header : {} ", requestHeader);

        String username = null;
        String token = null;
        // if header is not null and staring with Bearer then
        if (requestHeader != null && requestHeader.startsWith("Bearer")) {
            // extracting the token
            token = requestHeader.substring(7);
            try {
                username = this.jwtHelper.getUsernameFromToken(token);
            } catch (IllegalArgumentException e) {
                logger.info("Illegal Argument while fetching the username!!");
                e.printStackTrace();
            } catch (ExpiredJwtException e) {
                logger.info("Given jwt token is expired!!");
                e.printStackTrace();
                ;
            } catch (MalformedJwtException e) {
                logger.info("Token is change or malformed!!");
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else { // header is null
            if (requestHeader == null) {
                logger.debug("Authorization header is missing");
            } else {
                logger.debug("Authorization header does not start with Bearer");
            }
        }
        // now we have the username and the user is not already authenticated
        /*
                Two checks:
                    1️⃣ Username extracted successfully
                    2️⃣ User not already authenticated
        Why check authentication null?
        Because:
        If already authenticated, don’t override it.
         */
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // loading user from database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
            // if token is valid
            if (validateToken) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }else {
                logger.info("Validation fails!!");
            }
        }
        filterChain.doFilter(request,response);
    }
}
