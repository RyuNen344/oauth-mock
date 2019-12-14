package com.ryunen344.demo.oauth.config

import org.slf4j.Logger
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.security.KeyPair
import java.security.KeyPairGenerator

@Configuration
class KeyConfig(private val log : Logger) {

    @Bean
    fun keyPair() : KeyPair{
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(2048)
        val pair= keyGenerator.genKeyPair()

        log.debug("key public : {}", pair.public)
        log.debug("key secret : {}", pair.private)
        return pair
    }
}