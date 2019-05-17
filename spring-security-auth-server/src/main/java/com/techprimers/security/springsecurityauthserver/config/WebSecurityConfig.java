package com.techprimers.security.springsecurityauthserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER - 6)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${server.error.path:${error.path:/error}}") 
    private String urlError;

    /*@Autowired
    private AuthenticationManager authenticationManager;*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                    .antMatchers(urlError).permitAll()
                    .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth/*.parentAuthenticationManager(authenticationManager)*/
                .inMemoryAuthentication()
                .withUser("Peter")
                .password("peter")
                .roles("USER")
                .and().withUser("admin").password("admin").roles("ADMIN");
    }
    
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() 
      throws Exception {
        return super.authenticationManagerBean();
    }

    @SuppressWarnings("deprecation")
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
}
