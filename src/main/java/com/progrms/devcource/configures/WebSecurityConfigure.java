package com.progrms.devcource.configures;

import com.progrms.devcource.user.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.task.DelegatingSecurityContextAsyncTaskExecutor;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
@Slf4j
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    //    private DataSource dataSource;
//    @Autowired
//    public void setDataSource(DataSource dataSource) {
//        this.dataSource = dataSource;
//    }

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);

//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .usersByUsernameQuery(
//                        "SELECT " +
//                                "login_id, passwd, true " +
//                                "FROM " +
//                                "users " +
//                                "WHERE " +
//                                "login_id = ?"
//                )
//                .groupAuthoritiesByUsername(
//                        "SELECT " +
//                                "u.login_id, g.name, p.name " +
//                                "FROM " +
//                                "users u JOIN groups g ON u.group_id = g.id " +
//                                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                                "JOIN permissions p ON p.id = gp.permission_id " +
//                                "WHERE " +
//                                "u.login_id = ?"
//                )
//                .getUserDetailsService().setEnableAuthorities(false);
    }

    @Bean
    @Qualifier("myAsyncTaskExecutor")
    public ThreadPoolTaskExecutor threadPoolTaskExecutor(){
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setThreadNamePrefix("my-executor-");
        return executor;
    }

    @Bean
    public DelegatingSecurityContextAsyncTaskExecutor taskExecutor(
            @Qualifier("myAsyncTaskExecutor") ThreadPoolTaskExecutor delegate
    ) {
        return new DelegatingSecurityContextAsyncTaskExecutor(delegate);
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource){
//        JdbcDaoImpl jdbcDao = new JdbcDaoImpl();
//        jdbcDao.setDataSource(dataSource);
//        jdbcDao.setEnableAuthorities(false);
//        jdbcDao.setEnableGroups(true);
//        jdbcDao.setUsersByUsernameQuery(
//            "SELECT " +
//                "login_id, passwd, true " +
//            "FROM " +
//                "users " +
//            "WHERE " +
//                "login_id = ?"
//        );
//
//        jdbcDao.setGroupAuthoritiesByUsernameQuery(
//            "SELECT " +
//                "u.login_id, g.name, p.name " +
//            "FROM " +
//                "users u JOIN groups g ON u.group_id = g.id " +
//                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                "JOIN permissions p ON p.id = gp.permission_id " +
//            "WHERE " +
//                "u.login_id = ?"
//        );
//        return jdbcDao;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AccessDecisionManager accessDecisionManager(){
        List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
        decisionVoters.add(new WebExpressionVoter());
        decisionVoters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));
        return new UnanimousBased(decisionVoters);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/me", "/asyncHello", "/someMethod").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
                .anyRequest().permitAll()
                .and()

                .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()

                .httpBasic()
                .and()

                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()

                .rememberMe()
                .key("my-remember-me")
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()

                .anonymous()
                .principal("thisIsAnonymousUser")
                .authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
                .and()

                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
                .and()

                .sessionManagement()
                .sessionFixation().changeSessionId()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/")
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
                .and()
                .and()

//                .requiresChannel()
//                .anyRequest().requiresSecure()

                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }

}
