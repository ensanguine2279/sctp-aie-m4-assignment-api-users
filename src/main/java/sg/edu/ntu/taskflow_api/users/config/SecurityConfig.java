package sg.edu.ntu.taskflow_api.users.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import sg.edu.ntu.taskflow_api.users.security.JwtAuthFilter;
import sg.edu.ntu.taskflow_api.users.security.JwtService;
import sg.edu.ntu.taskflow_api.users.security.RestAuthenticationEntryPoint;
import sg.edu.ntu.taskflow_api.users.security.RestAccessDeniedHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

        private final JwtService jwtService;
        private final RestAuthenticationEntryPoint authenticationEntryPoint;
        private final RestAccessDeniedHandler accessDeniedHandler;

        // Spring calls this constructor and supplies both beans
        public SecurityConfig(
                        JwtService jwtService,
                        RestAuthenticationEntryPoint authenticationEntryPoint,
                        RestAccessDeniedHandler accessDeniedHandler) {
                this.jwtService = jwtService;
                this.authenticationEntryPoint = authenticationEntryPoint;
                this.accessDeniedHandler = accessDeniedHandler;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

                http
                                // REST APIs using stateless JWT auth do not need CSRF protection.
                                // CSRF is designed for browser-based session flows; since we never issue
                                // a session cookie, there is nothing for a cross-site request to hijack.
                                .csrf(csrf -> csrf.disable())

                                // Stateless: Spring Security will not create or use sessions.
                                // Every request must carry a valid JWT token.
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // Unauthenticated requests (missing or invalid tokens) get a 401 whose body is
                                // produced by GlobalExceptionHandler, via RestAuthenticationEntryPoint.
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint(authenticationEntryPoint)
                                                .accessDeniedHandler(accessDeniedHandler))

                                // /auth/login is public; everything else needs a valid token
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/auth/login").permitAll()
                                                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                                                .anyRequest().authenticated())
                                                

                                // Register JWT filter to run before username/password authentication
                                .addFilterBefore(new JwtAuthFilter(jwtService),
                                                UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}