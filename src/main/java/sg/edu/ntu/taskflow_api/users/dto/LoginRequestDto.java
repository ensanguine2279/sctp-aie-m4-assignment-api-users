package sg.edu.ntu.taskflow_api.users.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginRequestDto {

    @NotBlank(message = "Username must not be blank")
    @Size(max = 50, message = "Username is too long")
    private String username;

    @NotBlank(message = "Password must not be blank")
    @Size(max = 100, message = "Password is too long")
    private String password;
}
