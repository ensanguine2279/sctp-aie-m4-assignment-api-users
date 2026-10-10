package sg.edu.ntu.taskflow_api.users;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import sg.edu.ntu.taskflow_api.users.config.SecurityConfig;
import sg.edu.ntu.taskflow_api.users.security.RestAccessDeniedHandler;
import sg.edu.ntu.taskflow_api.users.security.RestAuthenticationEntryPoint;

/**
 * Loads the real security setup into a @WebMvcTest slice. Add any new security
 * bean here once, instead of editing every controller test.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({ SecurityConfig.class, RestAuthenticationEntryPoint.class, RestAccessDeniedHandler.class })
public @interface WithRealSecurity {
}