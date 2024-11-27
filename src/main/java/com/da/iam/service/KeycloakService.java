package com.da.iam.service;

import org.keycloak.admin.client.Keycloak;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class KeycloakService {

        @Autowired
        private Keycloak keycloak;

        public void syncUsers() {
            List<UserRepresentation> users = keycloak.realm("your-realm")
                    .users()
                    .list();

            users.forEach(user -> {
                String userId = user.getId();
                String email = user.getEmail();

                // Store or update user in your database
                // Example: userService.saveUser(new User(userId, email));
            });
        }

}
