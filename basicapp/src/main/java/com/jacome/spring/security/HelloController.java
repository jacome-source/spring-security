package com.jacome.spring.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
	
	@GetMapping("/hello")
	public String hello() {
		return "Hello World";
		
	}

	@GetMapping("/other")
	public String other() {
		return "other";
		
	}
}
