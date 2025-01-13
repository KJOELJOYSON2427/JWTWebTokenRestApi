package io.javabrains.springsecurityjwt.filters;

import io.javabrains.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomJwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtTokenUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken= extractJwtFromRequest(httpServletRequest);
        if(StringUtils.hasText(jwtToken)  && jwtTokenUtil.validateToken(jwtToken)){
            UserDetails userDetails=new User(jwtTokenUtil.getUsernameFromToken(jwtToken),"",jwtTokenUtil.getRolesFromToken(jwtToken));
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }else{
            System.out.println("Cannot set the Security Context");

        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    private String extractJwtFromRequest(HttpServletRequest request){
        String bearToken = request.getHeader("Authorization");
        if(StringUtils.hasText(bearToken) && bearToken.startsWith("Bearer ")){
            return bearToken.substring(7);
        }
        return null;
    }
}
