package com.example.demo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/")
public class LoginController {
    private final UserStore userStore;
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    public LoginController(UserStore userStore) {
        this.userStore = userStore;
    }

    @GetMapping("/login")
    public String login() {
        //return "redirect:/loginPage.html"; // 重定向到/static/loginPage.html
        logger.info("login");

        // 最好这样用：
        return "loginPage"; // thymeleaf视图解析器，找到默认路径/templates的loginPage.html
    }

    @PostMapping("/performLogin")
    @ResponseBody
    public ResponseEntity<?> performLogin(@RequestBody UserCredentials credentials, HttpServletRequest request) {
        boolean isAuthenticated = userStore.checkPassword(credentials.getUsername(), credentials.getPassword());
//        isAuthenticated = true;
        logger.info("isAuthenticated: " + isAuthenticated);
        if (isAuthenticated) {
            request.getSession().setAttribute("username", credentials.getUsername());
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            return ResponseEntity.ok(response);
            //return "redirect:/";
        } else {
            return ResponseEntity.status(401).body("Invalid credentials");
            //return "redirect:/login?error";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
//        return ResponseEntity.ok("Logged out successfully");
        return "redirect:/login";
    }

    @PostMapping("/addUser")
    @ResponseBody
    public ResponseEntity<?> addUser(@RequestBody UserCredentials userCredentials){
        logger.info("dfafdafdafadfa");
        if (userStore.addUser(userCredentials.getUsername(), userCredentials.getPassword())){
            return ResponseEntity.ok("User added Successfully");
        } else {
            return ResponseEntity.badRequest().body("The registering user is not permitted.");
        }
    }

    @PostMapping("/changePassword")
    @ResponseBody
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        logger.info("user: {}, pass: {}", request.getUsername(), request.getOldPassword());
        if (userStore.checkPassword(request.getUsername(), request.getOldPassword())) {
            userStore.changePassword(request.getUsername(), request.getNewPassword());
            return ResponseEntity.ok("Password changed Successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid current password");
        }
    }

//    @GetMapping("/logout")
//    public ResponseEntity<?> logout(HttpServletRequest request) {
//        HttpSession session = request.getSession(false);
//        if (session != null) {
//            session.invalidate();
//        }
//        return ResponseEntity.ok("Logged out successfully");
//    }

    @GetMapping("/currentUser")
    @ResponseBody
    public ResponseEntity<?> currentUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute("username") != null) {
            Map<String, String> response = new HashMap<>();
            response.put("username", session.getAttribute("username").toString());
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(401).body("No active session");
    }

    public static class UserCredentials {
        private String username;
        private String password;

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }

    public static class ChangePasswordRequest {
        private String username;
        private String oldPassword;
        private String newPassword;

        public String getUsername() {
            return username;
        }

        public String getOldPassword() {
            return oldPassword;
        }

        public String getNewPassword() {
            return newPassword;
        }
    }
}
