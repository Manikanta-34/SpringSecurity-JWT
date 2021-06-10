package com.security.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.security.jwt.model.JwtRequest;
import com.security.jwt.model.JwtResponse;
import com.security.jwt.service.UserService;
import com.security.jwt.utility.JwtUtility;

@RestController
public class WelcomeController {

	@Autowired
	private JwtUtility utility;

	@Autowired
	private AuthenticationManager auth;

	@Autowired
	private UserService userService;

	@GetMapping("/")
	public String welcome() {
		return "Welcome to Spring Security with JWT!!!!!";
	}

	@PostMapping("/auth")
	public ResponseEntity<Object> getToken(@RequestBody JwtRequest jwtRequest) throws Exception {
		try {
			auth.authenticate(
					new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
		} catch (Exception e) {
			return new ResponseEntity<>(new JwtResponse("Invalid credentials"), HttpStatus.BAD_REQUEST);
			// throw new ExpiredJwtException(null, null, "Invalid");
		}
		UserDetails userDetails = userService.loadUserByUsername(jwtRequest.getUsername());

		String generateToken = utility.generateToken(userDetails);
		return new ResponseEntity<>(new JwtResponse(generateToken), HttpStatus.OK);
	}
}
