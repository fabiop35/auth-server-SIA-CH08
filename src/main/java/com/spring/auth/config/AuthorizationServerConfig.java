package com.spring.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.Nullable;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfiguration
                .applyDefaultSecurity(http);
        return http
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(
            PasswordEncoder passwordEncoder) {
        //UUID.randomUUID().toString()
        RegisteredClient registeredClient
                //= RegisteredClient.withId("taco-admin-client")
                = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("client")
                        //.clientName("taco-admin-client")
                        //.id("taco-admin-client")
                        .clientSecret(passwordEncoder.encode("secret"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1:9090/login/oauth2/code/client")
                        .scope("writeIngredients")
                        .scope("deleteIngredients")
                        .scope(OidcScopes.OPENID)
                        .clientSettings(
                                clientSettings -> clientSettings.requireUserConsent(true))
                        .build();

        System.out.println("》clientID: " + registeredClient.getClientId());
        System.out.println("》clientName: " + registeredClient.getClientName());
        System.out.println("》Secret: " + registeredClient.getClientSecret());
        System.out.println("》ID: " + registeredClient.getId());
        System.out.println("》redirect: " + registeredClient.getRedirectUris());
        System.out.println("》expires: " + registeredClient.getClientSecretExpiresAt());
        System.out.println("[ Grant Type: " + registeredClient.getAuthorizationGrantTypes().toString());
        Set<AuthorizationGrantType> at = registeredClient.getAuthorizationGrantTypes();
        for (AuthorizationGrantType att : at) {
            System.out.println("Value " + att.getValue());
        }

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource()
            throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return new ProviderSettings().issuer("http://auth-server:9000");
        //return ProviderSettings.builder().issuer("http://127.0.0.1:9000").build();
    }

}
