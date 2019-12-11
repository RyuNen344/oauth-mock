package com.ryunen344.demo.oauth.security

import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.DefaultSecurityFilterChain

class JwtTokenFilterConfigurer(private val jwtTokenProvider : JwtTokenProvider) : SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>() {

    override fun configure(builder : HttpSecurity?) {
        super.configure(builder)
    }


}