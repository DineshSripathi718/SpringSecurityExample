package com.configuration.DAO;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.SpringProject.Model.Users;

@Repository
public interface UsersDao extends JpaRepository<Users, Integer>{

	Users getByUsername(String username);

}
