package com.github.foamdino.service;

import com.github.foamdino.model.entity.Category;
import com.github.foamdino.repository.CategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class LookupService {

    private final CategoryRepository categoryRepository;

    @Autowired
    public LookupService(CategoryRepository categoryRepository) {
        this.categoryRepository = categoryRepository;
    }

    public Iterable<Category> getAllCategories() {
        return categoryRepository.findAll();
    }
}
