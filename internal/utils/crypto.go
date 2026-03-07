package utils

import (
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "os"
)

// MD5Hash returns MD5 hash of a string
func MD5Hash(text string) string {
    hash := md5.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

// SHA1Hash returns SHA1 hash of a string
func SHA1Hash(text string) string {
    hash := sha1.Sum([]byte(text))
    return hex.EncodeToString(hash[:])
}

// SHA256Hash returns SHA256 hash of a string
func SHA256Hash(text string) string {
    hash := sha256.Sum256([]byte(text))
    return hex.EncodeToString(hash[:])
}

// FileHash computes SHA256 of a file
func FileHash(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer f.Close()
    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }
    return hex.EncodeToString(h.Sum(nil)), nil
}