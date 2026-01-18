package com.cos.security.repository;

import com.cos.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// JpaRepository를 상속했기 때문에 @Repository 어노테이션 없어도 됨
public interface UserRepository extends JpaRepository<User, Integer> {
}
