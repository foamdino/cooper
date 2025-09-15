package com.github.foamdino.model.entity;

import jakarta.persistence.*;

import java.sql.Timestamp;

@Entity(name = "orders")
public class Order {
   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private int id;
   @Column(name = "client_id")
   private int clientId;
   @Column(name = "payment_method")
   private String paymentMethod;
   @Column(name = "created_at")
   private Timestamp createdAt;

}