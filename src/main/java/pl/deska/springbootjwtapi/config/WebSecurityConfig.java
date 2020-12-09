package pl.deska.springbootjwtapi.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pl.deska.springbootjwtapi.filter.JwtFilter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()
               .antMatchers(HttpMethod.GET, "/api/books").hasAnyRole("ADMIN", "USER")
               .antMatchers(HttpMethod.POST,"/api/books").hasRole("ADMIN")
               .and()
               .addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class);

       http.csrf().disable();
    }
}
