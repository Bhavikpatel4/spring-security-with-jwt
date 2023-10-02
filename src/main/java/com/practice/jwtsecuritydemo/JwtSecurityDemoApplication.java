package com.practice.jwtsecuritydemo;

import com.practice.jwtsecuritydemo.auth.AuthenticationResponse;
import com.practice.jwtsecuritydemo.auth.AuthenticationService;
import com.practice.jwtsecuritydemo.auth.RegisterRequest;
import com.practice.jwtsecuritydemo.dto.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class JwtSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecurityDemoApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService authenticationService
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("Admin")
					.lastname("Admin")
					.username("admin@gmail.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
			AuthenticationResponse adminRes = authenticationService.register(admin);
			System.out.println("Admin Token : " + adminRes.getAccessToken());
			System.out.println("Admin Refresh Token : " + adminRes.getRefreshToken());

			var manager = RegisterRequest.builder()
					.firstname("Manager")
					.lastname("Manager")
					.username("manager@gmail.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			AuthenticationResponse managerRes = authenticationService.register(manager);
			System.out.println("Manager Token : " + managerRes.getAccessToken());
			System.out.println("Manager Refresh Token : " + managerRes.getRefreshToken());
		};
	}

}
