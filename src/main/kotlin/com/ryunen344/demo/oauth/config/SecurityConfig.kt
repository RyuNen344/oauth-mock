package com.ryunen344.demo.oauth.config

import com.ryunen344.demo.oauth.security.JwtAuthenticationEntryPoint
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
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig : WebSecurityConfigurerAdapter() {

    override fun configure(http : HttpSecurity) {

        // enable basic auth
        http.httpBasic().disable()
        http.formLogin().disable()
//        http.anonymous().disable()
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
                .exceptionHandling()
                .authenticationEntryPoint(JwtAuthenticationEntryPoint())
                .accessDeniedHandler(BearerTokenAccessDeniedHandler())
                .and()
                .authenticationProvider(JwtAuthenticationProvider(jwtDecoder()))
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(JwtBearerTokenAuthenticationConverter())
//                .authenticationManager(JwtAuthenticationManager(jwtDecoder()))
    }

    override fun configure(auth : AuthenticationManagerBuilder) {
        auth.authenticationProvider(JwtAuthenticationProvider(jwtDecoder()))
    }

//    @Bean
//    fun requestHeaderAuthenticationFilter() : RequestHeaderAuthenticationFilter {
//        val filter = RequestHeaderAuthenticationFilter()
//        filter.setAuthenticationManager(JwtAuthenticationManager(jwtDecoder()))
//        return filter
//    }

    @Bean
    fun jwtDecoder() : JwtDecoder {
        return NimbusJwtDecoder.withPublicKey(KeyPairGenerator.getInstance("RSA").genKeyPair().public as RSAPublicKey).build()
    }

//    @Bean
//    override fun authenticationManager() : AuthenticationManager {
//        return JwtAuthenticationManager(jwtDecoder())
//    }
}