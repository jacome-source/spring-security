package com.jacome.springcloud.security.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.PasswordLookup;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class AuthorizationServerConfiguration {

	private static final String ROLES_CLAIM = "roles";

	@Autowired
	private UserDetailsService userDetailsService;

	/**
	 * Dados da chave JWT injetados
	 */
	@Value("${keyFile}")
	private String keyFile;

	@Value("${password}")
	private String password;

	@Value("${alias}")
	private String alias;

	@Value("${providerUrl}")
	private String providerUrl;

	@Autowired
	private PasswordEncoder passwordEncoder;

	/**
	 * Filtro com maior precedência
	 * Realiza autenticação do login e validação HTTP
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
		// Aplica segurança padrão
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		// Usa userDetailsService customizado para o login no BD
		return http.userDetailsService(userDetailsService)
				.formLogin(Customizer.withDefaults()).build();

	}

	/**
	 * Autenticação com JWT
	 * Precisa das chaves JWT geradas
	 */
	
	// JWTDecoder será utilizado automaticamente na execução
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		// jwksource é o local onde as chaves podem ser lidas
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);

	}

	@Bean
	public JWKSource<SecurityContext> jwkSource()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		JWKSet jwkSet = buildJWKSet();
		// jwkSelector seleciona as chaves jwt
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

	}

	// Carrega as chaves JWT no set
	private JWKSet buildJWKSet() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		// Ler as chaves em hard code e armazena no set
		try (InputStream fis = this.getClass().getClassLoader().getResourceAsStream(keyFile);) {
			keyStore.load(fis, alias.toCharArray());
			// Utiliza o password ao tentar carregar a chave do store
			return JWKSet.load(keyStore, new PasswordLookup() {
				@Override
				public char[] lookupPassword(String name) {
					return password.toCharArray();
				}
			});
		}

	}

	/**
	 * Configuração do server como provider
	 */
	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer(providerUrl).build();

	}

	/**
	 * Configuração do cliente
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registredClient = RegisteredClient.withId("couponservice")
				.clientId("couponclientapp")
				.clientSecret(passwordEncoder.encode("9999"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				// ferramenta online de debug
				.redirectUri("https://oidcdebugger.com/debug")
				.scope("read").scope("write")
				.tokenSettings(tokenSettings())
				.build();
		return new InMemoryRegisteredClientRepository(registredClient);

	}

	// Tempo de duração do token
	@Bean
	public TokenSettings tokenSettings() {
		return TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofMinutes(30l)).build();

	}

	// Adiciona a informação dos Roles no token
	// Roles são adicionados na Authentication pelo userServiceDetails customizado
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
				Authentication principal = context.getPrincipal();
				Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toSet());
				context.getClaims().claim(ROLES_CLAIM, authorities);
			}
		};

	}

}
