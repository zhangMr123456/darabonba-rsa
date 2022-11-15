package com.alibabacloud.rsautil;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

public class Client {
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_SIGNATURE = "SHA1WithRSA";
    public static final Base64.Decoder b64Decoder = Base64.getMimeDecoder();
    public static final Base64.Encoder b64Encoder = Base64.getMimeEncoder();

    public static PrivateKey generatePrivate(byte[] encodedKey) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        return keyFactory.generatePrivate(keySpec);
    }

    public static PrivateKey getPrivateKeyFromString(String privateKeyStr) throws Exception {
        byte[] encodedKey = b64Decoder.decode(privateKeyStr);
        return generatePrivate(encodedKey);
    }

    public static byte[] shaSign(byte[] message, String privateKey) throws Exception {
        PrivateKey pKey = getPrivateKeyFromString(privateKey);
        Signature signature = Signature.getInstance(ALGORITHM_SIGNATURE);
        signature.initSign(pKey);
        signature.update(message);
        return signature.sign();
    };

    /**
     * 通过公钥加密数据
     * @param publicKey:
     * @param data:
     */
    public byte[] encrypt(String publicKey, byte[] data) throws Exception{
        byte[] raw = publicKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding8");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return cipher.doFinal(data);
    }

    /**
     * 通过私钥解密数据
     */
    public byte[] decrypt(String privateKey, byte[] data) throws Exception {
        byte[] raw = privateKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding8");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return cipher.doFinal(data);
    }

    public static byte[] bDecode(byte[] s){
        return b64Decoder.decode(s);
    }

    public static byte[] bEncode(byte[] s){
        return b64Encoder.encode(s);
    }

    public static String genTs() {
        long curTime = System.currentTimeMillis();
        return Long.toString(curTime);
    }

    public static String uuid(){
        UUID curUUID = UUID.randomUUID();
        return curUUID.toString();
    }
}