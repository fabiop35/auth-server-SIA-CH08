package com.spring.auth;

import com.spring.auth.users.User;
import com.spring.auth.users.UserRepository;
//import java.util.TimeZone;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthServerApplication {

    @Bean
    public ApplicationRunner dataLoader(
            UserRepository repo, PasswordEncoder encoder) {
        return args -> {
            repo.save(
               new User("anibal", encoder.encode("password"), "ROLE_ADMIN"));
            repo.save(
                    new User("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
        };
    }

    public static void main(String[] args) {
        //System.out.println("》》》Setting the timezone"+TimeZone.getTimeZone("GMT-5:00").getID());
        //TimeZone.setDefault(TimeZone.getTimeZone("GMT-5:00"));
        
    
        SpringApplication.run(AuthServerApplication.class, args);
    }

}
