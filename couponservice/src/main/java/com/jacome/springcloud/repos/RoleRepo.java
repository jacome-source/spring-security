package com.jacome.springcloud.repos;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jacome.springcloud.model.Role;

public interface RoleRepo extends JpaRepository<Role, Long> {

}
