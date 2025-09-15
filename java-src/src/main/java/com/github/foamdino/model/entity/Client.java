package com.github.foamdino.model.entity;

import jakarta.persistence.*;

@Entity(name = "clients")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String name;
    private String surnames;
    private String direction;
    private String state;
    @Column(name = "postal_code")
    private String postalCode;
    private String phone;
    private String email;
    @Column(name = "password_hash")
    private String passwordHash;

    public Client() {}

    public Client(int id, String name, String surnames, String direction, String state, String postalCode, String phone, String email, String passwordHash) {
        this.id = id;
        this.name = name;
        this.surnames = surnames;
        this.direction = direction;
        this.state = state;
        this.postalCode = postalCode;
        this.phone = phone;
        this.email = email;
        this.passwordHash = passwordHash;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurnames() {
        return surnames;
    }

    public void setSurnames(String surnames) {
        this.surnames = surnames;
    }

    public String getDirection() {
        return direction;
    }

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }
}
