package sg.edu.ntu.taskflow_api.users.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class TokenResponseDto {
    private String token;
    private Boolean valid;
    private ClaimsDto claims;
    private String error;
}
