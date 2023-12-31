package com.practice.jwtsecuritydemo.repo;

import com.practice.jwtsecuritydemo.entity.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
