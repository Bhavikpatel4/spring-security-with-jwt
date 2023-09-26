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
@RequestMapping("/api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("GET :: admin controller");
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public ResponseEntity<String> post() {
        return ResponseEntity.ok("POST :: admin controller");
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public ResponseEntity<String> put() {
        return ResponseEntity.ok("PUT :: admin controller");
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public ResponseEntity<String> delete() {
        return ResponseEntity.ok("DELETE :: admin controller");
    }
}
