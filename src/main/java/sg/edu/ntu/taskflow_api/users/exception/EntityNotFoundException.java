package sg.edu.ntu.taskflow_api.users.exception;

public class EntityNotFoundException extends RuntimeException {
    public EntityNotFoundException(String type, long id) {
        super(type + " with ID " + id + " not found");
    }

    public EntityNotFoundException(String type, String identifier, String value) {
        super(type + " with " + identifier + " " + value + " not found");
    }
}
