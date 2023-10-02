package com.practice.jwtsecuritydemo.config;

import com.practice.jwtsecuritydemo.repo.TokenRepo;
import com.practice.jwtsecuritydemo.repo.UserRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepo tokenRepo;
    private final JwtService jwtService;
    private final UserRepo userRepo;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        final String jwt = authHeader.substring(7);
        final String username = jwtService.extractUsername(jwt);

        if(username != null) {
            var user = userRepo.findByUsername(username).orElseThrow();
            var validTokens = tokenRepo.findAllValidTokensByUser(user.getId());
            validTokens.forEach(token -> {
                token.setRevoked(true);
                token.setExpired(true);
            });
            tokenRepo.saveAll(validTokens);
        }
    }
}
