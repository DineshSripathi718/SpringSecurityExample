package com.configuration.Service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.SpringProject.Model.Users;
import com.configuration.DAO.UsersDao;

@Service
public class DatabaseUserDetailsService implements UserDetailsService{
	
	@Autowired
	UsersDao usersDao;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Users user = usersDao.getByUsername(username);
		System.err.println(username);
		System.out.println("Inside the loadUserByUsername method");
		if(user == null) {
			System.err.println("User not found");
			throw new UsernameNotFoundException("User not found");
		}
		
		
		//custom class which will create object for the UserDetails
		return new UserPrincipal(user);
	}
	
}
