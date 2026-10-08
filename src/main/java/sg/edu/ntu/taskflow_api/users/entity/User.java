package sg.edu.ntu.taskflow_api.users.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Column;
import jakarta.persistence.OneToMany;
import jakarta.validation.constraints.Pattern;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder

@JsonPropertyOrder({ "id", "username", "password", "name" })
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private long id;

    @Column(name = "username", unique = true)
    @NotBlank(message = "Username is mandatory")
    @Size(min = 6, max = 20, message = "Username must be between 6 and 20 characters long")
    @Pattern(regexp = "^[a-z0-9]+$", message = "Username may only contain lowercase letters and digits")
    private String username;

    @Column(name = "password")
    @NotBlank(message = "Password is mandatory")
    @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters long")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ToString.Exclude
    private String password;

    @Column(name = "name")
    @NotBlank(message = "Name is mandatory")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters long")
    private String name;

    @Column(name = "role")
    @Enumerated(EnumType.STRING)
    @NotNull(message = "Role is mandatory")
    private UserRole role;

    public User(String username, String password, String name, UserRole role) {
        this.username = username;
        this.password = password;
        this.name = name;
        this.role = role;
    }
}
