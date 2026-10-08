package sg.edu.ntu.taskflow_api.users.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@Builder
@JsonPropertyOrder({ "id", "title", "description", "priority", "completed" })
// @Entity
@Table(name = "tasks")
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "title")
    @NotBlank(message = "Title is mandatory")
    private String title;

    @Column(name = "description")
    private String description;

    @Column(name = "priority")
    @Enumerated(EnumType.STRING)
    @NotNull(message = "Priority is mandatory")
    private TaskPriority priority;

    @Column(name = "completed")
    private boolean completed;

    @ManyToOne
    @JoinColumn(name = "user_id")
    // @JsonBackReference
    // @JsonIgnore
    // @ToString.Exclude
    @EqualsAndHashCode.Exclude
    private User user;

    // Constructor for creating a task with a unique ID generated automatically
    public Task(String title, String description, TaskPriority priority, boolean completed, User user) {
        this.title = title;
        this.description = description;
        this.priority = priority;
        this.completed = completed;
        this.user = user;
    }

    // Constructor for creating a task with priority as a string
    public Task(String title, String description, String priority, boolean completed, User user) {
        this(title, description, TaskPriority.valueOf(priority), completed, user);
    }

    public void setPriority(TaskPriority priority) {
        this.priority = priority;
    }

    // Sets the priority of the task using a string representation of the priority
    // enum
    public void setPriority(String priority) {
        this.priority = TaskPriority.valueOf(priority);
    }
}
