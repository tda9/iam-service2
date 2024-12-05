package com.da.iam.service;

import com.da.iam.entity.User;
import com.da.iam.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ImageService {
    @Value("${application.file.upload-dir}")
    public String uploadDir;
    private final UserRepo userRepo;
    public String saveImage(MultipartFile file, String userId) throws IOException {
        User user = userRepo.findById(UUID.fromString(userId))
                .orElseThrow(()-> new IllegalArgumentException("User not found"));
        Path uploadPath = Paths.get(uploadDir);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        String fileName = file.getOriginalFilename();
        Path filePath = uploadPath.resolve(fileName);
        user.setImage(uploadPath+"\\"+fileName);
        userRepo.save(user);
        Files.copy(file.getInputStream(), filePath, StandardCopyOption.REPLACE_EXISTING);
        return filePath.toString();
    }

}
