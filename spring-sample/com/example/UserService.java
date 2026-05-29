package com.example;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;
public class UserService {
    private final UserRepository repo;
    private final RestTemplate rest = new RestTemplate();
    public UserService(UserRepository repo) { this.repo = repo; }

    @Transactional                                        // -> Db (the proxy runs the transaction)
    public User register(String email) {
        User existing = repo.findByEmail(email);          // -> Db (Spring Data repo, bodyless)
        rest.getForObject("https://api.example.com/v?e=" + email, String.class); // -> Net
        return existing != null ? existing : new User(email);
    }

    public String pureFormat(User u) { return "user:" + u.email; }   // pure -> {}
}
