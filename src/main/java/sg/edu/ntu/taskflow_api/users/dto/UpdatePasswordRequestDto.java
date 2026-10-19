package sg.edu.ntu.taskflow_api.users.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdatePasswordRequestDto(
        @NotBlank(message = "Password is mandatory") @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters long") String password) {
}
