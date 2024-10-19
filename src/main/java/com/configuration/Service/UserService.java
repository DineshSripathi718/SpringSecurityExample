package com.configuration.Service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.SpringProject.Model.Users;
import com.configuration.DAO.UsersDao;

@Service
public class UserService {
	
	@Autowired
	UsersDao userDao;
	
	@Autowired
	AuthenticationManager authManager;
	
	@Autowired
	JwtService jwtService;
	
	public List<Users> getUsers(){
		List<Users> users = null;
		
		users = userDao.findAll();
		
		return users;
	}

	public Users registerUser(Users user) {
		System.out.println(user);
		// TODO Auto-generated method stub
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userDao.save(user);
	}

	public String verifyUser(Users user) {
		Authentication auth = authManager.authenticate
				(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
		
		if(auth.isAuthenticated())
			return jwtService.generateToken(user.getUsername());
		return "Failed";
	}
}
