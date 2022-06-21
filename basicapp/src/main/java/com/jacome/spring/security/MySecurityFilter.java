package com.jacome.spring.security;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Filtro customizado de segurança
 */
public class MySecurityFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		System.out.println("Antes");
		// Código anterior a chamada doFilter é executado no processo de ida ao Authentication Manager
		chain.doFilter(request, response);
		// Código posterior a chamada doFilter é executado no processo de volta do Authentication Manager
		System.out.println("Depois");
	}

}
