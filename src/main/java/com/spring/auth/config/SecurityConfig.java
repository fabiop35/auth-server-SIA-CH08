package com.spring.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.spring.auth.users.UserRepository;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

    return http
      .authorizeRequests(
        authorizeRequests
        -> authorizeRequests
         .mvcMatchers("/h2-console/**")
          .access("permitAll")
         .anyRequest().authenticated() )
     .csrf()
      .ignoringAntMatchers("/h2-console/**")
        .and().headers().frameOptions()
         .sameOrigin()
                .and()
                .formLogin()
            
            .and().httpBasic()
                .and().build();
    }

 @Bean
 public UserDetailsService userDetailsService(UserRepository userRepo) {
        return username -> userRepo.findByUsername(username);
    }

  @Bean
  public PasswordEncoder passwordEncoder() {
      PasswordEncoder p = NoOpPasswordEncoder.getInstance();
        return p;
  }
}
