package sg.edu.ntu.taskflow_api.users.exception;

public class UserNotFoundException extends EntityNotFoundException {
    public UserNotFoundException(long id) {
        super("User", id);
    }

    public UserNotFoundException(String username) {
        super("User", "username", username);
    }
}
