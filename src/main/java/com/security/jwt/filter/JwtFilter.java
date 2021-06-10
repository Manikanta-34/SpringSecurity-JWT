package com.security.jwt.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.jwt.service.UserService;
import com.security.jwt.utility.JwtUtility;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtility utility;
	@Autowired
	private UserService service;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authorization = request.getHeader("Authorization");
		String token = null;
		String userName = null;
		try {
			if (authorization != null && authorization.startsWith("Bearer ")) {
				token = authorization.substring(7);

				userName = utility.getUsernameFromToken(token);

			}
			if (userName != null) {
				UserDetails userDetails = service.loadUserByUsername(userName);

				if (utility.validateToken(token, userDetails)) {
					UsernamePasswordAuthenticationToken passwordAuthenticationToken = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					passwordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(passwordAuthenticationToken);
				}

			}
		} catch (ExpiredJwtException e) {
			request.setAttribute("exception", e);
			throw new ExpiredJwtException(null, null, e.getMessage(), e);
		} catch (MalformedJwtException e) {
			request.setAttribute("exception", e);
			throw new MalformedJwtException(e.getMessage());
		}

		filterChain.doFilter(request, response);
	}

}
