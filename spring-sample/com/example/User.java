package com.example;
import javax.persistence.Table;
@Table(name = "users")
public class User { public final String email; public User(String email) { this.email = email; } }
