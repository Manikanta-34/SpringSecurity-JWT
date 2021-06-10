package com.security.jwt.utility;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class JwtUtility {
	private static final long JWT_EXPIRATION = 60;

	// token generation
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<String, Object>();
		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String username) {
		return Jwts.builder().setClaims(claims).setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_EXPIRATION * 1000))
				.signWith(SignatureAlgorithm.HS512, "secret").compact();

	}

	public String getUsernameFromToken(String token) {

		return getClaimsFromToken(token, Claims::getSubject);
	}

	private <T> T getClaimsFromToken(String token, Function<Claims, T> claimsResolver) {
		Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		Claims body = null;
		try {
			body = Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
		} catch (ExpiredJwtException e) {

			throw new ExpiredJwtException(null, null, "Token expired", e);

		} catch (UnsupportedJwtException e) {

			e.printStackTrace();
		} catch (MalformedJwtException e) {

			throw new MalformedJwtException("Token is invalid");
		} catch (SignatureException e) {

			e.printStackTrace();
		} catch (IllegalArgumentException e) {

			e.printStackTrace();
		}

		return body;

	}

	public boolean validateToken(String token, UserDetails userDetails) {
		String usernameFromToken = getUsernameFromToken(token);
		return (usernameFromToken.equals(userDetails.getUsername()) && !isTokenExpired(token));

	}

	private boolean isTokenExpired(String token) {
		Date expirationTime = getExpirationTime(token);
		return expirationTime.before(new Date());

	}

	private Date getExpirationTime(String token) {
		Date claimsFromToken = getClaimsFromToken(token, Claims::getExpiration);
		return claimsFromToken;

	}

}
