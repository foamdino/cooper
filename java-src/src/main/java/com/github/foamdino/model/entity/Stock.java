package com.github.foamdino.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.persistence.*;

@Entity(name = "stock")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Stock {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int code;
    private String description;
    @JsonIgnore
    private byte[] image;
    @Column(name = "category_id")
    private int categoryId;
    private int quantity;
    private double price;
    private String status;
    @Column(name = "created_by")
    private int createdBy;
    @Column(name = "updated_by")
    private int updatedBy;

    public Stock() {}

    public Stock(int code, String description, int categoryId, int quantity, double price, String status, int createdBy, int updatedBy) {
        this.code = code;
        this.description = description;
        this.categoryId = categoryId;
        this.quantity = quantity;
        this.price = price;
        this.status = status;
        this.createdBy = createdBy;
        this.updatedBy = updatedBy;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public byte[] getImage() {
        return image;
    }

    public void setImage(byte[] image) {
        this.image = image;
    }

    public int getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(int categoryId) {
        this.categoryId = categoryId;
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

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(int createdBy) {
        this.createdBy = createdBy;
    }

    public int getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(int updatedBy) {
        this.updatedBy = updatedBy;
    }
}
