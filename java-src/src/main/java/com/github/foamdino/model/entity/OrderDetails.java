package com.github.foamdino.model.entity;

import jakarta.persistence.*;

@Entity(name = "order_details")
public class OrderDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "order_id")
    private int orderId;
    @Column(name = "product_code")
    private int productCode;
    private int quantity;
    private double price;

    public OrderDetails() {}

    public OrderDetails(int id, int orderId, int productCode, int quantity, double price) {
        this.id = id;
        this.orderId = orderId;
        this.productCode = productCode;
        this.quantity = quantity;
        this.price = price;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getOrderId() {
        return orderId;
    }

    public void setOrderId(int orderId) {
        this.orderId = orderId;
    }

    public int getProductCode() {
        return productCode;
    }

    public void setProductCode(int productCode) {
        this.productCode = productCode;
    }

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }
}
