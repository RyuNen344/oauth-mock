package com.ryunen344.demo.oauth.security

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationEntryPoint : AuthenticationEntryPoint {

    override fun commence(request : HttpServletRequest?, response : HttpServletResponse?, authException : AuthenticationException?) {

        response?.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")
        response?.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.reasonPhrase)
    }
}