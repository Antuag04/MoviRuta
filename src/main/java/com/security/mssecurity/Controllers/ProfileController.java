package com.security.mssecurity.Controllers;

import com.security.mssecurity.Models.Profile;
import com.security.mssecurity.Services.ProfileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/profiles")
public class ProfileController {

    @Autowired
    private ProfileService profileService;

    @GetMapping
    public List<Profile> find() {
        return this.profileService.find();
    }

    @GetMapping("/{id}")
    public Profile findById(@PathVariable String id) {
        return this.profileService.findById(id);
    }

    @PostMapping
    public Profile create(@RequestBody Profile newProfile) {
        return this.profileService.create(newProfile);
    }

    @PutMapping("/{id}")
    public Profile update(@PathVariable String id, @RequestBody Profile newProfile) {
        return this.profileService.update(id, newProfile);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable String id) {
        this.profileService.delete(id);
    }

}
