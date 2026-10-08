package sg.edu.ntu.taskflow_api.users.dto;

import java.time.Instant;
import java.util.List;

public record ClaimsDto(String username, List<String> roles, long expiration) {

    @Override
    public String toString() {
        return "ClaimsDto[username=" + username
                + ", roles=" + roles
                + ", expiration=" + expiration
                + ", expirationInstant=" + Instant.ofEpochMilli(expiration)
                + "]";
    }
}
