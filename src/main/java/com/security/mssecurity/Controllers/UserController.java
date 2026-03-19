package com.security.mssecurity.Controllers;
import com.security.mssecurity.Models.User;
import com.security.mssecurity.Services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> find() {
        return userService.find();
    }

    @GetMapping("{id}")
    public User findById(@PathVariable String id) {
        return userService.findById(id);
    }

    @PostMapping
    public User create(@RequestBody User usuario) {
        return userService.create(usuario);
    }

    @PutMapping("{id}")
    public User update(@PathVariable String id, @RequestBody User usuario) {
        return userService.update(id, usuario);
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        userService.delete(id);
    }



    @PostMapping("{userId}/profile/{profileId}")
    public ResponseEntity<Map<String, String>> addUserProfile(
            @PathVariable String userId,
            @PathVariable String profileId) {

        boolean response = this.userService.addProfile(userId, profileId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Profile not found"));
        }
    }

    @DeleteMapping("{userId}/profile/{profileId}")
    public ResponseEntity<Map<String, String>> deleteUserProfile(
            @PathVariable String userId,
            @PathVariable String profileId) {

        boolean response = this.userService.removeProfile(userId, profileId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Profile not found"));
        }
    }




    @PostMapping("{userId}/session/{sessionId}")
    public ResponseEntity<Map<String, String>> addUserSession(
            @PathVariable String userId,
            @PathVariable String sessionId) {

        boolean response = this.userService.addSession(userId, sessionId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Session not found"));
        }
    }
    @DeleteMapping("{userId}/session/{sessionId}")
    public ResponseEntity<Map<String, String>> deleteUserSession(
            @PathVariable String userId,
            @PathVariable String sessionId) {

        boolean response = this.userService.removeSession(userId, sessionId);
        if (response) {
            return ResponseEntity.ok(Map.of("message", "Success"));
        } else {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "User or Session not found"));
        }
    }


}