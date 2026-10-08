package sg.edu.ntu.taskflow_api.users.dto;

import java.time.Instant;

public record ErrorResponseDto(
                String message,
                Instant timestamp) {
}
