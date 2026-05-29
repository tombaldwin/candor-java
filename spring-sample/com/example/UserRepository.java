package com.example;
import org.springframework.data.repository.CrudRepository;
public interface UserRepository extends CrudRepository<User, Long> {
    User findByEmail(String email);   // Spring synthesizes the SQL impl at runtime — no bytecode
}
