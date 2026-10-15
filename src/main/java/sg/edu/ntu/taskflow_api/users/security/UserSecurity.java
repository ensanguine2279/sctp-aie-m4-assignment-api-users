package sg.edu.ntu.taskflow_api.users.security;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Rules used from @PreAuthorize expressions as @userSecurity.
 *
 * The caller's id comes from the verified token (the "uid" claim), so there is
 * no database lookup. It fails closed: no authentication, or an unexpected
 * principal type, means "not self".
 */
@Component("userSecurity")
public class UserSecurity {

    public boolean isSelf(long id, Authentication authentication) {
        return authentication != null
                && authentication.getPrincipal() instanceof AuthenticatedUser user
                && user.userId() == id;
    }
}