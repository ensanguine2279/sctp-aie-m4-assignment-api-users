package sg.edu.ntu.taskflow_api.users;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
class TaskflowApiUsersApplicationTests {

	@DynamicPropertySource
	static void jwtProperties(DynamicPropertyRegistry registry) {
		JwtKeysTest.register(registry);
	}

	@Test
	void contextLoads() {
	}
}
