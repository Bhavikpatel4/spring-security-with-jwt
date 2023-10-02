package com.practice.jwtsecuritydemo.exceptions;

import org.springframework.security.core.AuthenticationException;

public class InvalidJwtTokenException extends AuthenticationException {
    public InvalidJwtTokenException(String msg) {
        super(msg);
    }
}
