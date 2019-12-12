package com.ryunen344.demo.oauth.security

import org.slf4j.Logger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.BearerTokenError
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter

class JwtAuthenticationManager(private val jwtDecoder : JwtDecoder) : AuthenticationManager {

    @Autowired
    private lateinit var log : Logger

    companion object {
        private fun invalidToken(message : String?) : OAuth2Error? {
            return try {
                BearerTokenError(
                        BearerTokenErrorCodes.INVALID_TOKEN,
                        HttpStatus.UNAUTHORIZED,
                        message,
                        "https://tools.ietf.org/html/rfc6750#section-3.1")
            } catch (malformed : IllegalArgumentException) { // some third-party library error messages are not suitable for RFC 6750's error message charset
                invalidToken("An error occurred while attempting to decode the Jwt: Invalid token")
            }
        }
    }

    override fun authenticate(authentication : Authentication?) : Authentication {
        log.debug("authenticate")
        if (authentication == null || (authentication is BearerTokenAuthenticationToken).not()) throw JwtAuthenticationException("not authenticated")

        val token = (authentication as BearerTokenAuthenticationToken).token

        return try {
            log.debug("return authentication")
            JwtBearerTokenAuthenticationConverter().convert(jwtDecoder.decode(token)) as Authentication
        } catch (e : JwtException) {
            throw onError(e)
        }
    }

    private fun onError(e : JwtException) : OAuth2AuthenticationException {
        val invalidRequest = invalidToken(e.message)
        return OAuth2AuthenticationException(invalidRequest, invalidRequest?.description, e)
    }
}