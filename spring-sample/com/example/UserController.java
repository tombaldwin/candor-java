package com.example;
import org.springframework.web.bind.annotation.GetMapping;
public class UserController {
    private final UserService service;
    public UserController(UserService service) { this.service = service; }

    @GetMapping("/user")                                  // entry point; transitively Db + Net
    public User get(String email) { return service.register(email); }
}
