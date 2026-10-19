package sg.edu.ntu.taskflow_api.users.dto;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;

import sg.edu.ntu.taskflow_api.users.entity.UserRole;

public record UpdateUserRequestDto(
        @NotBlank(message = "Username is mandatory") @Size(min = 6, max = 20, message = "Username must be between 6 and 20 characters long") @Pattern(regexp = "^[a-z0-9]+$", message = "Username may only contain lowercase letters and digits") String username,
        @NotBlank(message = "Name is mandatory") @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters long") String name,
        @Enumerated(EnumType.STRING) @NotNull(message = "Role is mandatory") UserRole role) {
}
