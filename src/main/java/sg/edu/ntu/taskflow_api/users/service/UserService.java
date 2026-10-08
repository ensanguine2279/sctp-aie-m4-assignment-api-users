package sg.edu.ntu.taskflow_api.users.service;

import java.util.List;

import sg.edu.ntu.taskflow_api.users.entity.User;

public interface UserService {

    List<User> getAllUsers();

    User getUserById(long id);

    User getUserByUsername(String username);

    void createUser(User user);

    User updateUser(long id, User user);

    void deleteUser(long id);

}
