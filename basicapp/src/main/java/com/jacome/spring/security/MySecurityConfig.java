package com.jacome.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private MyAuthenticationProvider authenticationProvider;

	// Permite customizar o Authentication Manager
	/**
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	
		// Cria Authentication Manager com regras em memória
		// Outras opções são LDAP e BD
		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
		UserDetails user = User.withUsername("jacome").password(passwordEncoder.encode("jacome")).authorities("read").build();
		userDetailsService.createUser(user);
		
		auth.userDetailsService(userDetailsService);
	}
	*/
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Define o método de autenticação
		// -> Básica (Autenticação via rest)
		// -> Form Based (Oferece formulário default pra autenticar)
		// -> Oath
		http.formLogin();
	
		// Apenas endpoint hello é autenticado
		http.authorizeRequests().antMatchers("/hello").authenticated();
		
		// Todos os requests devem ser autenticados 
//		http.authorizeRequests().anyRequest().authenticated();

		// Adiciona um novo filtro no fluxo, depois de outro filtro
		http.addFilterAfter(new MySecurityFilter(), BasicAuthenticationFilter.class);
		
	}

	// Encriptador
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
