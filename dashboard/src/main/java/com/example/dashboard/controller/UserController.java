package com.example.dashboard.controller;

import com.example.dashboard.config.JwtProvider;
import com.example.dashboard.model.User;
import com.example.dashboard.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            return "이미 등록된 이메일입니다.";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "회원가입 성공";
    }
    @Autowired
    private JwtProvider jwtProvider;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginUser) {
        Optional<User> userOpt = userRepository.findByEmail(loginUser.getEmail());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body("이메일이 존재하지 않습니다.");
        }

        User user = userOpt.get();
        if (!passwordEncoder.matches(loginUser.getPassword(), user.getPassword())) {
            return ResponseEntity.status(401).body("비밀번호가 일치하지 않습니다.");
        }

        String token = jwtProvider.generateToken(user.getEmail());
        return ResponseEntity.ok(token);
    }

}
