package com.ryunen344.demo.oauth.controller

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.slf4j.Logger
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

@RestController
@RequestMapping(value = ["/auth"])
class AuthorizationController(private val log : Logger, private val keyPair : KeyPair) {

    @GetMapping(value = ["/token/gen"])
    fun authorize(session : HttpSession, res : HttpServletResponse) {
        log.debug("key public : {}", keyPair.public)
        log.debug("key secret : {}", keyPair.private)

        val payload = JWTClaimsSet.Builder()
                .subject("id")
                .issuer(session.id)
                .expirationTime(Date(Date().time + 60 * 10000))
                .build()

        val jwk : RSAKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
                .keyIDFromThumbprint()
                .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(jwk.keyID)
                .type(JOSEObjectType.JWT)
                .build()

        val signer : JWSSigner = RSASSASigner(keyPair.private as RSAPrivateKey)
        val signedJWT = SignedJWT(header, payload)
        signedJWT.sign(signer)

        res.setHeader("Authorization", " Bearer " + signedJWT.serialize())
    }
}