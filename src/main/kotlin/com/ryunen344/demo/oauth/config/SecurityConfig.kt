package com.ryunen344.demo.oauth.config

import com.ryunen344.demo.oauth.security.JwtAuthenticationEntryPoint
import org.slf4j.Logger
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler
import java.security.KeyPair
import java.security.interfaces.RSAPublicKey

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig(private val log : Logger, private val keyPair : KeyPair) : WebSecurityConfigurerAdapter() {

    override fun configure(http : HttpSecurity) {

        // enable default auth
        http.httpBasic().disable()
        http.formLogin().disable()
        http.csrf().disable()
        http.logout().disable()
        http.cors()

        // No session will be created or used by spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        http
                .authorizeRequests()
                .antMatchers("/auth/token/gen").permitAll()
                .antMatchers("/auth/token/refresh").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer()
                .authenticationEntryPoint(JwtAuthenticationEntryPoint())
                .accessDeniedHandler(BearerTokenAccessDeniedHandler())
                .jwt()
    }

    override fun configure(auth : AuthenticationManagerBuilder) {
        auth.authenticationProvider(JwtAuthenticationProvider(jwtDecoder()).apply {
            setJwtAuthenticationConverter(JwtBearerTokenAuthenticationConverter())
        })
    }

    @Bean
    fun jwtDecoder() : JwtDecoder {
        log.debug("key public : {}", keyPair.public)
        log.debug("key secret : {}", keyPair.private)
        return NimbusJwtDecoder.withPublicKey(keyPair.public as RSAPublicKey).build()
    }
}