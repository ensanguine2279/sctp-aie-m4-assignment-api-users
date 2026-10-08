package sg.edu.ntu.taskflow_api.users.exception;

public class InvalidTokenException extends RuntimeException {

    public enum Reason {
        EXPIRED, BAD_SIGNATURE, MALFORMED, EMPTY
    }

    private final Reason reason;

    public InvalidTokenException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public InvalidTokenException(Reason reason, String message) {
        this(reason, message, null);
    }

    public Reason getReason() {
        return reason;
    }
}