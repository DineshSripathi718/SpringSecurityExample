package com.SpringProject.Controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.SpringProject.Model.Users;
import com.configuration.Service.UserService;

@RestController
public class HomeController {
	
	@Autowired
	public UserService userService;
	
	@GetMapping("/homepage")
	public String homepage() {
        return "Welcome to home page";
    }
	
	@GetMapping("/")
	public String home() {
		return "Logged in";
	}
	
	@GetMapping("/getUsers")
	public List<Users> getUsers(){
		return userService.getUsers();								
	}
	
	@PostMapping("/register")
	public Users register(@RequestBody Users user) {	
        return userService.registerUser(user);
//		return user;
    }
	
	@PostMapping("/loginUser")
	public String login(@RequestBody Users user) {
		return userService.verifyUser(user);
	}
}
