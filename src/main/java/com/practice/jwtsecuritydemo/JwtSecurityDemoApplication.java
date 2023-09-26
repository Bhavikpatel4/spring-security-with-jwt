package com.practice.jwtsecuritydemo;

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
			System.out.println("Admin Token : " + authenticationService.register(admin).getToken());

			var manager = RegisterRequest.builder()
					.firstname("Manager")
					.lastname("Manager")
					.username("manager@gmail.com")
					.password("password")
					.role(Role.MANAGER)
					.build();
			System.out.println("Manager Token : " + authenticationService.register(manager).getToken());
		};
	}

}
