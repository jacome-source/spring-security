package com.jacome.springcloud.repos;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jacome.springcloud.model.Product;

public interface ProductRepo extends JpaRepository<Product, Long> {

}
