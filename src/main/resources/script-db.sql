-- Create Users table
CREATE TABLE users (
                       id BIGSERIAL PRIMARY KEY,
                       uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       phone_number VARCHAR(20),
                       password_hash VARCHAR(255),
                       status user_status DEFAULT 'ACTIVE',
                       failed_attempt INT DEFAULT 0,
                       last_login_at TIMESTAMP,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       CONSTRAINT email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT phone_check CHECK (phone_number ~* '^\+?[1-9]\d{1,14}$')
);

-- Create OTP table
CREATE TABLE otp (
                     id BIGSERIAL PRIMARY KEY,
                     uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
                     user_id BIGINT NOT NULL,
                     code VARCHAR(6) NOT NULL,
                     type otp_type NOT NULL,
                     status otp_status DEFAULT 'PENDING',
                     attempts INT DEFAULT 0,
                     expiry_time TIMESTAMP NOT NULL,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                     CONSTRAINT code_check CHECK (code ~ '^[0-9]{6}$')
    );

-- Create Rate Limiting table
CREATE TABLE rate_limit (
                            id BIGSERIAL PRIMARY KEY,
                            user_id BIGINT NOT NULL,
                            ip_address VARCHAR(45) NOT NULL,
                            endpoint VARCHAR(255) NOT NULL,
                            request_count INT DEFAULT 1,
                            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            blocked_until TIMESTAMP,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create Authentication Tokens table
CREATE TABLE auth_tokens (
                             id BIGSERIAL PRIMARY KEY,
                             user_id BIGINT NOT NULL,
                             token VARCHAR(255) NOT NULL,
                             device_info VARCHAR(255),
                             ip_address VARCHAR(45),
                             is_valid BOOLEAN DEFAULT true,
                             expiry_time TIMESTAMP NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone_number);
CREATE INDEX idx_otp_user_id ON otp(user_id);
CREATE INDEX idx_otp_code ON otp(code);
CREATE INDEX idx_rate_limit_user_ip ON rate_limit(user_id, ip_address);
CREATE INDEX idx_auth_tokens_user ON auth_tokens(user_id);
CREATE INDEX idx_auth_tokens_token ON auth_tokens(token);

-- Create trigger function for updating timestamp
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updating timestamp
CREATE TRIGGER update_users_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_otp_timestamp
    BEFORE UPDATE ON otp
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_rate_limit_timestamp
    BEFORE UPDATE ON rate_limit
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();

CREATE TRIGGER update_auth_tokens_timestamp
    BEFORE UPDATE ON auth_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_timestamp();

-- Create cleanup function for expired OTPs
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS void AS $$
BEGIN
UPDATE otp
SET status = 'EXPIRED'
WHERE status = 'PENDING'
  AND expiry_time < CURRENT_TIMESTAMP;

DELETE FROM otp
WHERE status = 'EXPIRED'
  AND created_at < CURRENT_TIMESTAMP - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- Create cleanup function for expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
DELETE FROM auth_tokens
WHERE expiry_time < CURRENT_TIMESTAMP
   OR is_valid = false;
END;
$$ LANGUAGE plpgsql;

-- Comments on tables
COMMENT ON TABLE users IS 'Stores user information and authentication details';
COMMENT ON TABLE otp IS 'Stores OTP codes and their validation status';
COMMENT ON TABLE rate_limit IS 'Tracks API request rates for rate limiting';
COMMENT ON TABLE auth_tokens IS 'Stores authentication tokens after successful OTP validation';