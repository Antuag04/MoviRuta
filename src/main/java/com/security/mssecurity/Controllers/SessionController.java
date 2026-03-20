package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Session;
import com.security.mssecurity.Services.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    @Autowired
    private SessionService sessionService;

    @GetMapping
    public List<Session> find() {
        return this.sessionService.find();
    }

    @GetMapping("/{id}")
    public Session findById(@PathVariable String id) {
        return this.sessionService.findById(id);
    }

    @PostMapping
    public Session create(@RequestBody Session newSession) {
        return this.sessionService.create(newSession);
    }

    @PutMapping("/{id}")
    public Session update(@PathVariable String id, @RequestBody Session newSession) {
        return this.sessionService.update(id, newSession);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.sessionService.delete(id);
    }

}
