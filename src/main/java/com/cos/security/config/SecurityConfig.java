package com.cos.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
// Spring Boot + Spring Security 6 이후부터는 기본 SecurityFilterChain이 자동 구성되기 때문에 @EnableWebSecurity를 직접 선언하지 않아도 보안 필터 체인이 활성화
@EnableWebSecurity
// EnableGlobalMethodSecurity 는 deprecated 되어서 EnableMethodSecurity 사용
// Secured 어노테이션 활성화, preAuthorize 어노테이션 활성화 (기본이 true임), prePostEnabled는 deprecated 되어 기본으로 true임
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 URL
                        .requestMatchers("/manager/**").hasAnyRole("ADMIN","MANAGER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll())
                .formLogin(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")
                        // 로그인 성공 시 기본적으로 "/"로 이동하며, 인증이 필요한 특정 URL에서 접근한 경우 해당 URL로 리다이렉트
                        .defaultSuccessUrl("/"))
                .oauth2Login(oauth2 -> oauth2
                        // 구글 로그인이 완료된 뒤에 후처리가 필요
                        .loginPage("/loginForm"));
        return http.build();
    }
}
