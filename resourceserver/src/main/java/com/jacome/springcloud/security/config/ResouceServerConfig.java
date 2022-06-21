package com.jacome.springcloud.security.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ResouceServerConfig {
	private static final String ROLES_CLAIM = "roles";

	// Extrai os roles do JWT Token para ser usado no método abaixo para autenticação nas páginas
	@Bean
	public Converter<Jwt, Collection<GrantedAuthority>> jwtToAuthorityConverter() {
		return new Converter<Jwt, Collection<GrantedAuthority>>() {
			@Override
			public Collection<GrantedAuthority> convert(Jwt jwt) {
				List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);
				if (roles != null) {
					return roles.stream().map(eachRole -> new SimpleGrantedAuthority(eachRole))
							.collect(Collectors.toList());
				}
				return Collections.emptyList();
			}

		};

	}

	// Autenticação das páginas
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtToAuthorityConverter());
		
		http.authorizeRequests(authorizeRequests -> {
			authorizeRequests.mvcMatchers(HttpMethod.GET, "/couponapi/coupons/{code:^[A-Z]*$}")
					.hasAnyRole("USER", "ADMIN").mvcMatchers(HttpMethod.POST, "/couponapi/coupons").hasRole("ADMIN");
		}).oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
		return http.build();

	}
}
