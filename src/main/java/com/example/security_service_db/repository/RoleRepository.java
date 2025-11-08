package com.example.security_service_db.repository;


import com.example.security_service_db.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByRoleName(String roleName);

}

