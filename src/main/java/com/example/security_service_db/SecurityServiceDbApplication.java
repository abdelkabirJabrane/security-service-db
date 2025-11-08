package com.example.security_service_db;

import com.example.security_service_db.entities.Role;

import com.example.security_service_db.entities.User;

import com.example.security_service_db.repository.RoleRepository;

import com.example.security_service_db.repository.UserRepository;

import org.springframework.boot.CommandLineRunner;

import org.springframework.boot.SpringApplication;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import org.springframework.context.annotation.Bean;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;

import java.util.Optional;

import java.util.Set;

@SpringBootApplication

public class SecurityServiceDbApplication {

	public static void main(String[] args) {

		SpringApplication.run(SecurityServiceDbApplication.class, args);

	}

	@Bean

	CommandLineRunner init(UserRepository userRepository,

						   RoleRepository roleRepository,

						   PasswordEncoder passwordEncoder) {

		return args -> {

			// Check if admin already exists

			Optional<User> existingAdmin = userRepository.findByUsername("admin");

			if (existingAdmin.isEmpty()) {

				// Create or get ADMIN role

				Optional<Role> optAdminRole = Optional.ofNullable(roleRepository.findByRoleName("ROLE_ADMIN"));

				Role adminRole;

				if (optAdminRole.isPresent()) {

					adminRole = optAdminRole.get();

				} else {

					adminRole = new Role();

					adminRole.setRoleName("ROLE_ADMIN");

					adminRole = roleRepository.save(adminRole);

				}

				// Create or get USER role

				Optional<Role> optUserRole = Optional.ofNullable(roleRepository.findByRoleName("ROLE_USER"));

				Role userRole;

				if (optUserRole.isPresent()) {

					userRole = optUserRole.get();

				} else {

					userRole = new Role();

					userRole.setRoleName("ROLE_USER");

					userRole = roleRepository.save(userRole);

				}

				// Create admin user

				User admin = new User();

				admin.setUsername("admin");

				admin.setPassword(passwordEncoder.encode("admin123"));

				admin.setEnabled(true);

				Set<Role> adminRoles = new HashSet<>();

				adminRoles.add(adminRole);

				adminRoles.add(userRole);

				admin.setRoles(adminRoles);

				userRepository.save(admin);

			}

			Optional<User> existingUser = userRepository.findByUsername("user");

			if (existingUser.isEmpty()) {

				// Create or get USER role

				Optional<Role> optUserRole = Optional.ofNullable(roleRepository.findByRoleName("ROLE_USER"));

				User user = new User();

				user.setUsername("user");

				user.setPassword(passwordEncoder.encode("user123"));

				user.setEnabled(true);

				Set<Role> userRoles = new HashSet<>();

				userRoles.add(optUserRole.get());

				user.setRoles(userRoles);

				userRepository.save(user);

			}

		};

	}

}
