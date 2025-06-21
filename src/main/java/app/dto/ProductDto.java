package app.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

//PRODUCT THAT TAKES NAME AND PRICE
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProductDto {
    private String name;
    private BigDecimal price;
}
