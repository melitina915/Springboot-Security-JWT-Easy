package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 토큰 : cos 이걸 만들어줘야 함.
// id, pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 응답해준다.
// 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 온다.
// 그 때 토큰이 넘어오면 해당 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다.
// (RSA, HS256)

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// login 요청해서 username, password 전송하면 post로
// UsernamePasswordAuthenticationFilter가 동작한다.
// UsernamePasswordAuthenticationFilter는 로그인을 진행하는 필터이기 때문에
// AuthenticationManager를 통해서 로그인을 진행한다.

	private final AuthenticationManager authenticationManager;
	
	// Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
		// /login 요청이 들어오면 이를 UsernamePasswordAuthentication이 받아 attemptAuthentication 함수에서 처리한다.

		System.out.println("JwtAuthenticationFilter : 진입");

		// 1. username, password를 받아
		// 2. 정상인지 로그인 시도를 해본다.
		// authenticationManager로 로그인 시도를 하면 PrincipalDetailsService가 호출되어 loadUserByUsername 함수가 실행된다.
		// 해당 함수가 실행되어 PrincipalDetails가 리턴되면 PrincipalDetails는 세션에서 받는다.
		// 3. PrincipalDetails를 (권한 관리를 위해) 세션에 담고
		// 4. JWT 토큰을 만들어서 응답해주면 된다.
		// 세션에 담지 않으면 권한 관리가 되지 않는다.

		// request에 있는 username과 password를 파싱해서 자바 Object로 받기
		ObjectMapper om = new ObjectMapper();
		// ObjectMapper라는 클래스가 JSON 데이터를 파싱해준다.
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
			// InputStream 안에 username과 password가 담겨있다.
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("JwtAuthenticationFilter : "+loginRequestDto);
		
		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken =
		// 로그인 시도를 위해 직접 토큰을 만들어야 한다.
		// 원래 폼로그인을 하면 자동으로 토큰이 생성된다.
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(), 
						loginRequestDto.getPassword());
		// 이렇게 만든 토큰으로 로그인 시도를 해본다.
		
		System.out.println("JwtAuthenticationFilter : 토큰생성완료");
		
		// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
		// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
		// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인으로 리턴해준다.
		
		// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
		// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
		// 결론은 인증 프로바이더에게 알려줄 필요가 없음.
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
		// DB에 있는 username과 password가 일치하면 인증이 된다.
		// 토큰을 날린다.
		// 그러면 PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴된다.
		// AuthenticationManager에 토큰을 넣어 던지면 인증을 받게 된다.
		// 그러면 authentication에는 로그인 한 정보가 담긴다.

		PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
		// 세션에 저장된 authentication에 있는 Principal 객체를 가져와서 로그인을 한다.
		System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
		return authentication;
		// authentication 객체가 session 영역에 저장되고 이를 return한다.
		// return하는 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것이다.
		// 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다.
		// 단지 권한 처리때문에 세션을 넣어준다.
	}

	// JWT Token 생성해서 response에 담아주기
	// attemptAuthentication 실행 후 정상적으로 인증되면 successfulAuthentication 함수가 실행된다.
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
		
		String jwtToken = JWT.create()
				.withSubject(principalDetailis.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
	}
	
}
