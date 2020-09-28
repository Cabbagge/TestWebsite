package com.testwebsite.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter //WebSecurityConfigurerAdapter REMEMBER dis
{
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        //USER NAME AND PASSWORD
        auth.inMemoryAuthentication()
            .withUser("user")
            .password("password")
            .roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/").permitAll()    //Permits all without logging in
            .anyRequest().hasRole("USER").and()   //Any other requests needs authentication
            .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
            .logout()
                .logoutUrl("/logout")
                .permitAll();
            
    }
    
}
