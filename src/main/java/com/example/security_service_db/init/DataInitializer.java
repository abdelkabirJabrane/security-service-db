package com.example.security_service_db.init;


import com.example.security_service_db.entities.Role;
import com.example.security_service_db.entities.User;
import com.example.security_service_db.repository.RoleRepository;
import com.example.security_service_db.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class DataInitializer {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void initData() {
        // Créer les rôles
        Role adminRole = roleRepository.save(new Role(null, "ROLE_ADMIN"));
        Role userRole = roleRepository.save(new Role(null, "ROLE_USER"));

        // Créer les utilisateurs
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("1234"));
        admin.setRoles(Set.of(adminRole, userRole));
        userRepository.save(admin);

        User user = new User();
        user.setUsername("user1");
        user.setPassword(passwordEncoder.encode("1234"));
        user.setRoles(Set.of(userRole));
        userRepository.save(user);
    }
}
