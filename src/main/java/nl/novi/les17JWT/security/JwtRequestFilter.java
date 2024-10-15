package nl.novi.les17JWT.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;

    private final JwtService jwtService;

    public JwtRequestFilter(JwtService jwtService, UserDetailsService udService) {
        this.jwtService = jwtService;
        this.userDetailsService = udService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String jwt = extractJwtFromRequest(request);
        if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            processTokenAndSetAuthentication(jwt, request);
        }

        filterChain.doFilter(request, response);
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    private void processTokenAndSetAuthentication(String jwt, HttpServletRequest request) {
        String username = jwtService.extractUsername(jwt);
        if (username != null && jwtService.validateToken(jwt)) {
            List<GrantedAuthority> roles = jwtService.extractSimpleGrantedAuthorities(jwt);
            setAuthentication(username, roles, request, jwt);
        }
    }

    private void setAuthentication(String username, List<GrantedAuthority> roles,
                                   HttpServletRequest request, String jwt) {
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, roles);

        ApiUserDetails userDetails = new ApiUserDetails(username, jwtService.extractRoles(jwt), jwtService.extractOrganisation(jwt));
        authenticationToken.setDetails(userDetails);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

}
