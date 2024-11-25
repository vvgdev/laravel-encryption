<?php

namespace PHPCodersNp\DBEncryption;

use Illuminate\Support\Facades\Log;
use RuntimeException;

class Encrypter
{
    private static $method = 'aes-256-cbc'; // AES-128-CBC or AES-256-CBC

    /**
     * @param string $value
     * 
     * @return string
     * @throws RuntimeException
     */
    public static function encrypt($value)
    {
        $key = self::getKey();

        // Dynamically determine the IV length based on the encryption method
        $ivLength = openssl_cipher_iv_length(self::$method);  // This adjusts automatically for AES-128, AES-256, etc.

        // Generate a random IV of the determined length
        $iv = openssl_random_pseudo_bytes($ivLength);
        // $iv = '1111111111111111';

        // Perform AES encryption with the dynamic IV length
        $encrypted = openssl_encrypt(
            $value,
            self::$method, // Ensure this matches the encryption method (e.g., 'AES-128-CBC', 'AES-256-CBC')
            $key,
            0,
            $iv
        );

        if ($encrypted === false) {
            throw new RuntimeException('Encryption failed');
        }

        // Concatenate the IV and encrypted value, then base64-encode the result
        return base64_encode($iv . $encrypted);
    }

    /**
     * @param string $value
     * 
     * @return string
     * @throws RuntimeException
     */
    public static function decrypt($value)
    {
        // Decode the base64-encoded string
        $decodedData = base64_decode($value);
        if ($decodedData === false) {
            throw new RuntimeException('Failed to decode base64 data.');
        }

        // Determine the IV length based on the cipher method
        $ivLength = openssl_cipher_iv_length(self::$method);

        // Ensure decoded data is at least as long as the IV
        if (strlen($decodedData) < $ivLength) {
            throw new RuntimeException('Invalid encrypted data: insufficient length.');
        }

        // Extract the IV (the first bytes based on IV length)
        $iv = substr($decodedData, 0, $ivLength);
        $encryptedValue = substr($decodedData, $ivLength);

        // Decrypt the value using the CBC mode and the extracted IV
        $decryptedValue = openssl_decrypt(
            $encryptedValue,
            self::$method,
            self::getKey(),
            0,
            $iv
        );

        if ($decryptedValue === false) {
            throw new RuntimeException('Decryption failed. Data may be tampered with.');
        }

        return $decryptedValue;
    }

    /**
     * Get app key for encryption key
     *
     * @return string
     * @throws RuntimeException
     */
    protected static function getKey()
    {
        // Use a hash of the application's key (or any custom key you want)
        $key = config('laravelDatabaseEncryption.encrypt_key');
        if (empty($key)) {
            throw new RuntimeException('Encryption key not set in configuration.');
        }

        $salt = substr(hash('sha256', $key), 0, 32); // Ensure 32 bytes for AES-256 and 16 bytes for AES-128
        if (strlen($salt) !== 32) {
            throw new RuntimeException('Invalid encryption key length.');
        }

        return $salt;
    }
}
