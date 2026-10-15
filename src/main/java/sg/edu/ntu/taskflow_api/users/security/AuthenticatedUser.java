package sg.edu.ntu.taskflow_api.users.security;

import java.security.Principal;

/**
 * Who is calling, as read from a verified token: the username ("sub") and the user's
 * database id ("uid"). JwtAuthFilter puts it in the SecurityContext, so security rules such
 * as UserSecurity.isSelf can compare ids without a database lookup. It implements Principal,
 * so Authentication.getName() still returns the username.
 *
 * This is the principal of an authenticated REQUEST. The principal produced by a LOGIN is
 * AppUserDetails, which also carries the password hash and is never kept after login.
 */
public record AuthenticatedUser(String username, long userId) implements Principal {

    @Override
    public String getName() {
        return username;
    }
}