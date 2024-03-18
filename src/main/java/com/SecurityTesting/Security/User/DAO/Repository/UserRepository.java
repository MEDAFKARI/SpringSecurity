package com.SecurityTesting.Security.User.DAO.Repository;

import com.SecurityTesting.Security.User.DAO.Entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String Email);
}
