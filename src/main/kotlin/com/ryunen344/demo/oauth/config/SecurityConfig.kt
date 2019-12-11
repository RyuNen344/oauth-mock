package com.ryunen344.demo.oauth.config

import com.ryunen344.demo.oauth.security.JwtAuthenticationManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter
import javax.crypto.KeyGenerator


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig : WebSecurityConfigurerAdapter() {

    override fun configure(http : HttpSecurity) {

        // enable basic auth
        http.httpBasic().disable()
        http.formLogin().disable()
        http.anonymous().disable()
        http.csrf().disable()
        http.logout().disable()

        // No session will be created or used by spring security
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

        http
                .authorizeRequests()
                .antMatchers("/auth/token/gen").permitAll()
                .antMatchers("/auth/token/refresh").permitAll()
                .anyRequest().authenticated()
                .and()
                .authenticationProvider(JwtAuthenticationProvider(jwtDecoder()))
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(JwtBearerTokenAuthenticationConverter())
                .authenticationManager(JwtAuthenticationManager(jwtDecoder()))
    }

    @Bean
    fun jwtDecoder() : JwtDecoder {
        return NimbusJwtDecoder.withSecretKey(KeyGenerator.getInstance("AES").generateKey()).build()
    }

    @Bean
    override fun authenticationManager() : AuthenticationManager {
        return JwtAuthenticationManager(jwtDecoder())
    }
}