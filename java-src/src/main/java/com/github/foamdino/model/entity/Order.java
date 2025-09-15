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

    public Order() {}

    public Order(int id, int clientId, String paymentMethod, Timestamp createdAt) {
        this.id = id;
        this.clientId = clientId;
        this.paymentMethod = paymentMethod;
        this.createdAt = createdAt;
    }

   public int getId() {
      return id;
   }

   public void setId(int id) {
      this.id = id;
   }

   public int getClientId() {
      return clientId;
   }

   public void setClientId(int clientId) {
      this.clientId = clientId;
   }

   public String getPaymentMethod() {
      return paymentMethod;
   }

   public void setPaymentMethod(String paymentMethod) {
      this.paymentMethod = paymentMethod;
   }

   public Timestamp getCreatedAt() {
      return createdAt;
   }

   public void setCreatedAt(Timestamp createdAt) {
      this.createdAt = createdAt;
   }
}