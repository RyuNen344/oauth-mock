package com.ryunen344.demo.oauth.controller

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.servlet.http.HttpServletResponse


@RestController
@RequestMapping(value = ["/auth"])
class AuthorizationController {


    @GetMapping(value = ["/token/gen"])
    fun authorize(res : HttpServletResponse) {
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(2048)
        val kp = keyGenerator.genKeyPair()
        val publicKey = kp.public as RSAPublicKey
        val privateKey = kp.private as RSAPrivateKey

        val payload = JWTClaimsSet.Builder()
                .build()

        val jwk : RSAKey = RSAKey.Builder(publicKey)
                .keyIDFromThumbprint()
                .build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(jwk.keyID)
                .type(JOSEObjectType.JWT)
                .build()

        val signer : JWSSigner = RSASSASigner(privateKey)
        val signedJWT = SignedJWT(header, payload)
        signedJWT.sign(signer)
        res.setHeader("Authorization", " Bearer " + signedJWT.serialize())

    }


}