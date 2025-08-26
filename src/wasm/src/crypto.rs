//! 密码学工具库
//! 
//! 实现哈希函数、数字签名、加密解密、密钥管理等密码学功能

use sha2::{Sha256, Digest};
use rand::{Rng, RngCore, thread_rng};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, PasswordHash};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use pbkdf2::Pbkdf2;
use pbkdf2::password_hash::{rand_core::OsRng as Pbkdf2OsRng, PasswordHash as Pbkdf2PasswordHash, PasswordHasher as Pbkdf2PasswordHasher, PasswordVerifier as Pbkdf2PasswordVerifier};
use std::collections::HashMap;
use crate::types::VotingError;

/// 哈希函数封装
pub struct HashUtils;

impl HashUtils {
    /// 计算SHA256哈希
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
    
    /// 计算双重SHA256哈希
    pub fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first_hash = Self::sha256(data);
        Self::sha256(&first_hash)
    }
    
    /// 计算带盐的哈希
    pub fn sha256_with_salt(data: &[u8], salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

/// 随机数生成器
pub struct RandomUtils;

impl RandomUtils {
    /// 生成32字节随机数
    pub fn random_32_bytes() -> [u8; 32] {
        let mut rng = thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    }
    
    /// 生成指定长度的随机字节
    pub fn random_bytes(length: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        let mut bytes = vec![0u8; length];
        rng.fill_bytes(&mut bytes);
        bytes
    }
    
    /// 生成随机u64
    pub fn random_u64() -> u64 {
        let mut rng = thread_rng();
        rng.gen()
    }
    
    /// 生成指定范围的随机数
    pub fn random_range(min: u64, max: u64) -> u64 {
        let mut rng = thread_rng();
        rng.gen_range(min..max)
    }
}

/// 数字签名工具
pub struct SignatureUtils;

impl SignatureUtils {
    /// 生成Ed25519密钥对
    pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
        let mut rng = thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }
    
    /// 签名消息
    pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
        signing_key.sign(message)
    }
    
    /// 验证签名
    pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
    
    /// 从字节数组创建签名密钥
    pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> Result<SigningKey, VotingError> {
        Ok(SigningKey::from_bytes(bytes))
    }
    
    /// 从字节数组创建验证密钥
    pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, VotingError> {
        VerifyingKey::from_bytes(bytes).map_err(|_| VotingError::InvalidState)
    }
}

/// 加密解密工具
pub struct EncryptionUtils;

impl EncryptionUtils {
    /// 使用AES-256-GCM加密
    pub fn encrypt_aes_gcm(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, VotingError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        
        cipher.encrypt(nonce.into(), plaintext)
            .map_err(|_| VotingError::StorageError)
    }
    
    /// 使用AES-256-GCM解密
    pub fn decrypt_aes_gcm(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, VotingError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        
        cipher.decrypt(nonce.into(), ciphertext)
            .map_err(|_| VotingError::StorageError)
    }
    
    /// 生成随机密钥
    pub fn generate_key() -> [u8; 32] {
        RandomUtils::random_32_bytes()
    }
    
    /// 生成随机nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let random_bytes = RandomUtils::random_bytes(12);
        nonce.copy_from_slice(&random_bytes);
        nonce
    }
}

/// 密码哈希工具
pub struct PasswordUtils;

impl PasswordUtils {
    /// 使用Argon2哈希密码
    pub fn hash_password_argon2(password: &str) -> Result<String, VotingError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        argon2.hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| VotingError::StorageError)
    }
    
    /// 验证Argon2密码
    pub fn verify_password_argon2(password: &str, hash: &str) -> Result<bool, VotingError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| VotingError::StorageError)?;
        
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
    
    /// 使用PBKDF2哈希密码
    pub fn hash_password_pbkdf2(password: &str) -> Result<String, VotingError> {
        let salt = SaltString::generate(&mut Pbkdf2OsRng);
        
        Pbkdf2.hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| VotingError::StorageError)
    }
    
    /// 验证PBKDF2密码
    pub fn verify_password_pbkdf2(password: &str, hash: &str) -> Result<bool, VotingError> {
        let parsed_hash = Pbkdf2PasswordHash::new(hash)
            .map_err(|_| VotingError::StorageError)?;
        
        Ok(Pbkdf2.verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

/// 密钥管理工具
pub struct KeyManager {
    keys: HashMap<String, Vec<u8>>,
}

impl KeyManager {
    /// 创建新的密钥管理器
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    
    /// 生成新密钥
    pub fn generate_key(&mut self, key_id: &str) -> Result<[u8; 32], VotingError> {
        let key = RandomUtils::random_32_bytes();
        self.keys.insert(key_id.to_string(), key.to_vec());
        Ok(key)
    }
    
    /// 获取密钥
    pub fn get_key(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(|k| k.as_slice())
    }
    
    /// 删除密钥
    pub fn remove_key(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }
    
    /// 轮换密钥
    pub fn rotate_key(&mut self, key_id: &str) -> Result<[u8; 32], VotingError> {
        self.remove_key(key_id);
        self.generate_key(key_id)
    }
    
    /// 列出所有密钥ID
    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_utils() {
        let data = b"test data";
        let hash1 = HashUtils::sha256(data);
        let hash2 = HashUtils::sha256(data);
        assert_eq!(hash1, hash2);
        
        let double_hash = HashUtils::double_sha256(data);
        assert_ne!(hash1, double_hash);
    }

    #[test]
    fn test_random_utils() {
        let bytes1 = RandomUtils::random_32_bytes();
        let bytes2 = RandomUtils::random_32_bytes();
        assert_ne!(bytes1, bytes2);
        
        let range_num = RandomUtils::random_range(1, 100);
        assert!(range_num >= 1 && range_num < 100);
    }

    #[test]
    fn test_signature_utils() {
        let (signing_key, verifying_key) = SignatureUtils::generate_keypair();
        let message = b"test message";
        let signature = SignatureUtils::sign_message(&signing_key, message);
        
        assert!(SignatureUtils::verify_signature(&verifying_key, message, &signature));
        
        let wrong_message = b"wrong message";
        assert!(!SignatureUtils::verify_signature(&verifying_key, wrong_message, &signature));
    }

    #[test]
    fn test_encryption_utils() {
        let key = EncryptionUtils::generate_key();
        let nonce = EncryptionUtils::generate_nonce();
        let plaintext = b"secret message";
        
        let ciphertext = EncryptionUtils::encrypt_aes_gcm(&key, &nonce, plaintext).unwrap();
        let decrypted = EncryptionUtils::decrypt_aes_gcm(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_password_utils() {
        let password = "test_password";
        let hash = PasswordUtils::hash_password_argon2(password).unwrap();
        
        assert!(PasswordUtils::verify_password_argon2(password, &hash).unwrap());
        assert!(!PasswordUtils::verify_password_argon2("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_key_manager() {
        let mut key_manager = KeyManager::new();
        let key_id = "test_key";
        
        let key1 = key_manager.generate_key(key_id).unwrap();
        let retrieved_key = key_manager.get_key(key_id).unwrap();
        assert_eq!(key1.as_slice(), retrieved_key);
        
        let key2 = key_manager.rotate_key(key_id).unwrap();
        assert_ne!(key1, key2);
        
        assert!(key_manager.remove_key(key_id));
        assert!(key_manager.get_key(key_id).is_none());
    }
}
