package com.rayen.users.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTAuthorizationFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // Log the request URL for better tracking
        logger.info("Incoming request to: {}", request.getRequestURI());

        String jwt = request.getHeader("Authorization");

        // Log the presence or absence of the Authorization header
        if (jwt == null || !jwt.startsWith("Bearer ")) {
            logger.warn("Authorization header missing or invalid.");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Log the raw token
            logger.info("Raw JWT Token: {}", jwt);

            // Create a JWT verifier with the secret key
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecParams.SECRET)).build();

            // Remove the "Bearer " prefix and log the actual token used for verification
            jwt = jwt.substring(7);
            logger.info("JWT Token after removing Bearer prefix: {}", jwt);

            // Verify the token
            DecodedJWT decodedJWT = verifier.verify(jwt);
            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaim("roles").asList(String.class);

            // Log the decoded details from the JWT
            logger.info("Decoded JWT Subject (Username): {}", username);
            logger.info("Decoded JWT Roles: {}", roles);

            // Build authorities list
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
                logger.info("Granted Authority: {}", role);
            }

            // Create an authentication token and set it in the security context
            UsernamePasswordAuthenticationToken user =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(user);

        } catch (Exception e) {
            // Log any error that occurs during the token verification process
            logger.error("Error verifying JWT token: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
