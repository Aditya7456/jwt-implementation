package com.jwt.example.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtHelper {
    //requirement :
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    //    public static final long JWT_TOKEN_VALIDITY =  60;
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";
    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    /*
        When request comes:
        Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...
        You must extract:
        Username
        This method does that.
     */
    // Extract username (subject) from JWT token
    public String getUsernameFromToken(String token){
        return getClaimFromToken(token, Claims::getSubject);
    }
    /*
        Why needed?
        To check:
        Has token expired?
     */
    // Extract expiration date from JWT token
    public Date getExpirationDateFromToken(String token){
        return getClaimFromToken(token,Claims::getExpiration);
    }
    /*
        Why needed?
        This is a generic method.
     */
    // Extract any claim from token using resolver function
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver){
        Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // Parse token and return all claims using secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser() // it parse the jwt token
                .setSigningKey(secret) // Sets the secret key used to verify signature.
                .parseClaimsJws(token) // Split token into 3 parts
                .getBody(); // Returns payload (claims) as a Claims object.
    }

    // Check whether token has expired
    private Boolean isTokenExpired(String token){
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date()); // true if expired else false
        /*
        Means:
            date1.before(date2);
        👉 Is date1 earlier than date2?
            Is expiration time earlier than now?"
            Expiration = 25 Feb 2026 14:00
            Now         = 25 Feb 2026 15:30
            expiration.before(now) → true
            ✔ Token is expired
         */
    }

    // Validate token by checking username and expiration
    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    /*
        Why needed?
        This is the main validation logic.
        It checks:
            ✔ Username matches
            ✔ Token not expired
        If both true → token valid.
        This method is used inside:
        👉 JWT Filter
     */

    // Generate JWT token for authenticated user
    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return doGenerateToken(claims,userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    /*
        What it does step by step:
            1️⃣ Set claims (custom data)
            2️⃣ Set subject (username)
            3️⃣ Set issued time
            4️⃣ Set expiration
            5️⃣ Sign with secret using HS512
            6️⃣ Convert to compact string
     */

    // Build and sign JWT token with claims, subject, issue date and expiration
    private String doGenerateToken(Map<String, Object> claims, String username) {

        Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /*
        When is this used?
        When user logs in successfully.
        Example:  POST /login
        After authentication success → generate token.
     */
}
