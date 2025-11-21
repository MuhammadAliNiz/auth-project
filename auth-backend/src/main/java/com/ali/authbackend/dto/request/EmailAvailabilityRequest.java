package com.ali.authbackend.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailAvailabilityRequest {
    @Email(message = "Email must be valid")
    @NotBlank(message = "Email must not be blank")
    private String email;
}
