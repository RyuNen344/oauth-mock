package com.ryunen344.demo.oauth.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(value = ["/hello"])
class GreetingController {

    @GetMapping
    fun sayHello() : String = "hello!"


}