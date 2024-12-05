-- Drop the tables in reverse order of dependencies
DROP TABLE IF EXISTS password_reset_token CASCADE;
DROP TABLE IF EXISTS black_list_token CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS user_audit CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
-- Create the `users` table
-- Enable the uuid-ossp extension (PostgreSQL-specific, run this only once per database)
CREATE
EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the `users` table
CREATE TABLE users
(
    user_id     UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Auto-generated UUID
    email       VARCHAR(255) NOT NULL UNIQUE,                   -- Unique email
    password    VARCHAR(255) NOT NULL,
    phone       VARCHAR(15),
    dob         DATE,
    image       VARCHAR(255),                                   -- URL to the user's image
    is_verified BOOLEAN,
    deleted     BOOLEAN DEFAULT FALSE                           -- Soft delete user
);

-- Create the `roles` table
CREATE TABLE roles
(
    role_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Auto-generated UUID
    name    VARCHAR(50) NOT NULL UNIQUE                  -- Role name, e.g., 'ADMIN', 'USER'
);

-- Create the `permissions` table
CREATE TABLE permissions
(
    permission_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Auto-generated UUID
    name          VARCHAR(50) NOT NULL UNIQUE                  -- Permission name, e.g., 'READ', 'WRITE'
);

-- Create the `user_roles` table (many-to-many relationship between users and roles)
CREATE TABLE user_roles
(
    user_id     UUID,                                -- Foreign key to `users`
    role_id     UUID,                                -- Foreign key to `roles`
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Timestamp when the role was assigned
    PRIMARY KEY (user_id, role_id),                  -- Composite primary key
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE
);

-- Create the `role_permissions` table (many-to-many relationship between roles and permissions)
CREATE TABLE role_permissions
(
    role_id       UUID,                                -- Foreign key to `roles`
    permission_id UUID,                                -- Foreign key to `permissions`
    assigned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Timestamp when the permission was assigned
    PRIMARY KEY (role_id, permission_id),              -- Composite primary key
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE,
    CONSTRAINT fk_permission FOREIGN KEY (permission_id) REFERENCES permissions (permission_id) ON DELETE CASCADE
);

-- Create the `password_reset_token` table
CREATE TABLE password_reset_token
(
    token_id        UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Auto-generated UUID
    token           VARCHAR(255) NOT NULL,                       -- The unique password reset token
    expiration_date TIMESTAMP    NOT NULL,                       -- When the token expires
    user_id         UUID         NOT NULL,                       -- Foreign key to `users`
    CONSTRAINT fk_user_password_reset FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

-- Create the `black_list_token` table
CREATE TABLE black_list_token
(
    token_id        UUID DEFAULT uuid_generate_v4() PRIMARY KEY, -- Auto-generated UUID
    token           VARCHAR(255) NOT NULL,                       -- The token string itself
    expiration_date TIMESTAMP    NOT NULL,                       -- Expiration date of the token
    user_id         UUID         NOT NULL,                       -- Foreign key to `users`
    CONSTRAINT fk_user_blacklist FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);
--Để lấy access token mới với refresh token thì trong request để lấy access token, các bạn chỉ cần truyền grant_type=refresh_token, giá trị của refresh token mà chúng ta có trong request lấy access token trước, client ID và client secret.
-- -- Insert default roles
-- Insert permissions with UUIDs
INSERT INTO public.permissions (permission_id, deleted, resource_code, resource_name, scope)
VALUES
    (gen_random_uuid(), false, 'PERMISSIONS', 'TAT_CA_QUYEN_DOC_PERMISSION', 'READ'),
    (gen_random_uuid(), false, 'PERMISSIONS', 'TAT_CA_QUYEN_SUA_PERMISSION', 'UPDATE'),
    (gen_random_uuid(), false, 'PERMISSIONS', 'TAT_CA_QUYEN_XOA_PERMISSION', 'DELETE'),
    (gen_random_uuid(), false, 'PERMISSIONS', 'TAT_CA_QUYEN_TAO_PERMISSION', 'CREATE'),

    (gen_random_uuid(), false, 'ROLES', 'TAT_CA_QUYEN_DOC_ROLES', 'READ'),
    (gen_random_uuid(), false, 'ROLES', 'TAT_CA_QUYEN_SUA_ROLES', 'UPDATE'),
    (gen_random_uuid(), false, 'ROLES', 'TAT_CA_QUYEN_XOA_ROLES', 'DELETE'),
    (gen_random_uuid(), false, 'ROLES', 'TAT_CA_QUYEN_TAO_ROLES', 'CREATE'),

    (gen_random_uuid(), false, 'USERS', 'TAT_CA_QUYEN_DOC_USERS', 'READ'),
    (gen_random_uuid(), false, 'USERS', 'TAT_CA_QUYEN_SUA_USERS', 'UPDATE'),
    (gen_random_uuid(), false, 'USERS', 'TAT_CA_QUYEN_XOA_USERS', 'DELETE'),
    (gen_random_uuid(), false, 'USERS', 'TAT_CA_QUYEN_TAO_USERS', 'CREATE');

-- Insert the ADMIN role with a UUID
INSERT INTO public.roles (role_id, deleted, name)
VALUES (gen_random_uuid(), false, 'ADMIN');

-- Use variables to reference UUIDs for role and permissions
DO $$
    DECLARE
        admin_role_id UUID;
        permission_record RECORD;
    BEGIN
        -- Retrieve the UUID of the ADMIN role
        SELECT role_id INTO admin_role_id FROM public.roles WHERE name = 'ADMIN';

        -- Loop through all permissions to assign them to the ADMIN role
        FOR permission_record IN
            SELECT permission_id, resource_code, scope FROM public.permissions
            LOOP
                INSERT INTO public.role_permissions (permission_id, role_id, resource_code, scope)
                VALUES (permission_record.permission_id, admin_role_id, permission_record.resource_code, permission_record.scope);
            END LOOP;
    END $$;

