package com.cos.jwtex01.config;



import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtex01.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtex01.repository.UserRepository;
import org.springframework.web.filter.CorsFilter;

@Configuration
// IoC 할 수 있도록
@EnableWebSecurity
// 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	private final UserRepository userRepository;
	private final CorsConfig corsConfig;
	private final CorsFilter corsFilter;

//	@Autowired
//	private UserRepository userRepository;
//
//	@Autowired
//	private CorsConfig corsConfig;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				//.addFilter(corsConfig.corsFilter())
				.addFilter(corsFilter)
				// @CrossOrigin(인증 X), 시큐리티 필터에 등록 인증 (O)
				// corsFilter 등록
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				// JWT이므로 세션을 사용하지 않는 STATELESS 서버로 만들겠다는 의미
				// STATELESS는 세션을 사용하지 않겠다는 의미
			.and()
				.formLogin().disable()
				// ID, PW로 폼 로그인을 하지 않는 JWT 서버이므로 disable
				.httpBasic().disable()
				// 기본적인 http 로그인 방식들을 전혀 쓰지 않는다

				.addFilter(new JwtAuthenticationFilter(authenticationManager()))
				// UsernamePasswordAuthenticationFilter는 로그인을 진행하는 필터이기 때문에
				// AuthenticationManager를 통해서 로그인을 진행한다.
				// WebSecurityConfigurerAdapter가 AuthenticationManager를 가지고 있다.
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
				.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
					.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
					.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();
				// 이외 요청은 권한과 상관없이 모두 접근 가능
	}
}






