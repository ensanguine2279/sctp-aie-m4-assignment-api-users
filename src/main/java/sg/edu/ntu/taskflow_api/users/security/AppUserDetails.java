package sg.edu.ntu.taskflow_api.users.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Spring Security's User plus the database id. It lets the login flow read the
 * id from the authenticated principal, so the "uid" claim needs no second
 * database query.
 */
public class AppUserDetails extends User {

    private static final long serialVersionUID = 1L;

    private final long id;

    public AppUserDetails(
            long id, String username, String password,
            Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.id = id;
    }

    public long getId() {
        return id;
    }
}