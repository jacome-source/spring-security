package com.jacome.springcloud.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

/**
 * Implementação da lógica de login
 */
@Service
public class SecurityServiceImpl implements SecurityService {

	@Autowired
	UserDetailsService userDetailsService;

	@Autowired
	AuthenticationManager authenticationManger;

	@Override
	public boolean login(String userName, String password) {
		// userDetailsService realiza consulta na base
		UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, password,
				userDetails.getAuthorities());
		authenticationManger.authenticate(token);
		boolean result = token.isAuthenticated();

		if (result) {
			// Seta o token de autenticação no objeto context compartilhado
			SecurityContextHolder.getContext().setAuthentication(token);
		}
		return result;
	}

}
