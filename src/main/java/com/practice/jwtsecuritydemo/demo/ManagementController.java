package com.practice.jwtsecuritydemo.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/management")
@PreAuthorize("hasAnyRole('ADMIN','MANAGER')")
public class ManagementController {

    @GetMapping
    @PreAuthorize("hasAnyAuthority('admin:read','management:read')")
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("GET :: management controller");
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('admin:create','management:create')")
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("POST :: management controller");
    }

    @PutMapping
    @PreAuthorize("hasAnyAuthority('admin:update','management:update')")
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("PUT :: management controller");
    }

    @DeleteMapping
    @PreAuthorize("hasAnyAuthority('admin:delete','management:delete')")
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("DELETE :: management controller");
    }
}
