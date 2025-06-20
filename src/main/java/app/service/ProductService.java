package app.service;

import app.model.Product;
import app.repository.ProductRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ProductService {
    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    //Get all products
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    //Get product by id
    public Optional<Product> getProductById(Long id) {
        return productRepository.findById(id);
    }

    //Save/Update product
    public Product saveProduct(Product product) {
        return productRepository.save(product);
    }

    //delete product
    public void deleteProduct(Long id) {
        productRepository.deleteById(id);
    }
}
