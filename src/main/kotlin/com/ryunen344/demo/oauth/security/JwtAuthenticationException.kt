package com.ryunen344.demo.oauth.security

import org.springframework.security.core.AuthenticationException

class JwtAuthenticationException(msg : String?, th : Throwable?) : AuthenticationException(msg, th) {
    constructor(msg : String?) : this(msg, null)
}