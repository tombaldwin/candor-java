package com.example;
import org.springframework.web.client.RestTemplate;
import java.nio.file.Files;
import java.nio.file.Path;
class GoodService { private final RestTemplate rest; GoodService(RestTemplate r){rest=r;} void fetch(){ rest.getForObject("http://x", String.class); } }
class LeakyService { private final RestTemplate rest; LeakyService(RestTemplate r){rest=r;} String read(){ rest.getForObject("http://x", String.class); try { return Files.readString(Path.of("/etc/hostname")); } catch (Exception e){ return ""; } } }
class IdleService { private final RestTemplate rest; IdleService(RestTemplate r){rest=r;} String hello(){ return "hi"; } }
