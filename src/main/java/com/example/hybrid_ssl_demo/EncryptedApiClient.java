package com.example.hybrid_ssl_demo;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.*;

class EncryptedApiClient {
    // 클라이언트 RSA 키쌍
    static final String CLIENT_PRIVATE_KEY_PEM = readClasspath("/keys/client_priv_pkcs8.pem");
    // static final String CLIENT_PUBLIC_KEY_PEM  = readClasspath("/keys/client_pub_x509.pem"); // 사용하지 않음. 보관용

    // 서버 공개키. 서버에게 보낼 데이터 암호화
    static final String SERVER_PUBLIC_KEY_PEM  = readClasspath("/keys/server_pub_x509.pem");

    static String readClasspath(String path) {
        try (InputStream is = EncryptedApiClient.class.getResourceAsStream(path)) {
            if (is == null) throw new IllegalArgumentException("클래스패스 리소스 없음: " + path);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("리소스 읽기 실패: " + path, e);
        }
    }

    public static void main(String[] args) throws Exception {
        String api = "http://localhost:8080/api/secure"; // 먼저 Spring Boot 서버 실행 필요

        // 1) 보낼 평문 JSON 준비
        String payload = "{" +
                "\"message\":\"Hello from client\"," +
                "\"ts\":\"" + System.currentTimeMillis() + "\"}";

        // 2) AES-256 세션키와 12바이트 IV 생성
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aes = kg.generateKey();
        byte[] aesKey = aes.getEncoded();
        byte[] iv = randomIv12();

        // 3) 평문을 AES-GCM으로 암호화
        byte[] cipher = encryptAesGcm(aesKey, iv, payload.getBytes(StandardCharsets.UTF_8));

        // 4) (AES키 || IV)를 서버 공개키로 RSA-OAEP 암호화 => ek
        RSAPublicKey serverPub = (RSAPublicKey) loadPublicKeyX509(SERVER_PUBLIC_KEY_PEM);
        byte[] wrap = rsaOaepEncrypt(serverPub, ByteBuffer.allocate(32 + 12).put(aesKey).put(iv).array());

        // 5) (ek || data)에 클라이언트 개인키로 RSA-PSS 서명
        RSAPrivateKey clientPriv = (RSAPrivateKey) loadPrivateKeyPKCS8(CLIENT_PRIVATE_KEY_PEM);
        byte[] toSign = ByteBuffer.allocate(wrap.length + cipher.length).put(wrap).put(cipher).array();
        byte[] sig = signRsaPssSha256(clientPriv, toSign);

        // 6) 요청 JSON 만들기
        Map<String, String> req = new LinkedHashMap<>();
        req.put("clientId", "client-1");
        req.put("ek", Base64.getEncoder().encodeToString(wrap));
        req.put("data", Base64.getEncoder().encodeToString(cipher));
        req.put("sig", Base64.getEncoder().encodeToString(sig));
        String jsonReq = toJson(req);

        // 7) POST 전송
        String jsonRes = httpPostJson(api, jsonReq);
        System.out.println("서버로부터 받은 암호화 값: " + jsonRes);

        // 8) 응답 파싱(resIV, data, sig)
        Map<String, String> resMap = parseFlatJson(jsonRes);
        byte[] resIv   = Base64.getDecoder().decode(resMap.get("resIV"));
        byte[] resData = Base64.getDecoder().decode(resMap.get("data"));
        byte[] resSig  = Base64.getDecoder().decode(resMap.get("sig"));

        // 9) (resIV || resData)에 대한 서버 서명 검증
        RSAPublicKey serverPublic = (RSAPublicKey) loadPublicKeyX509(SERVER_PUBLIC_KEY_PEM);
        byte[] signed2 = ByteBuffer.allocate(resIv.length + resData.length).put(resIv).put(resData).array();
        verifyRsaPssSha256(serverPublic, signed2, resSig);

        // 10) 같은 AES 키로 응답 복호화
        byte[] plainRes = decryptAesGcm(aesKey, resIv, resData);
        System.out.println("서버로부터 받은 암호화 값 복호화 결과: " + new String(plainRes, StandardCharsets.UTF_8));
    }

    // ===== 클라이언트 공용 유틸 =====

    // 12바이트 길이의 랜덤 IV(초기화 벡터)를 생성
    static byte[] randomIv12() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // AES-GCM으로 평문을 암호화
    static byte[] encryptAesGcm(byte[] key, byte[] iv, byte[] plain) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.GCMParameterSpec spec = new javax.crypto.spec.GCMParameterSpec(128, iv);
        javax.crypto.SecretKey sk = new javax.crypto.spec.SecretKeySpec(key, "AES");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, sk, spec);
        return c.doFinal(plain);
    }

    // AES-GCM으로 암호문을 복호화
    static byte[] decryptAesGcm(byte[] key, byte[] iv, byte[] cipher) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.GCMParameterSpec spec = new javax.crypto.spec.GCMParameterSpec(128, iv);
        javax.crypto.SecretKey sk = new javax.crypto.spec.SecretKeySpec(key, "AES");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, sk, spec);
        return c.doFinal(cipher);
    }

    // RSA-OAEP(SHA-256, MGF1-SHA-256)로 짧은 데이터를 암호화
    static byte[] rsaOaepEncrypt(PublicKey pub, byte[] msg) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        javax.crypto.spec.OAEPParameterSpec oaep = new javax.crypto.spec.OAEPParameterSpec(
                "SHA-256", "MGF1",
                java.security.spec.MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified.DEFAULT);
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, pub, oaep);
        return c.doFinal(msg);
    }

    // RSA-PSS(SHA-256)로 바이트 배열에 서명
    static byte[] signRsaPssSha256(PrivateKey priv, byte[] msg) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        s.setParameter(pss);
        s.initSign(priv);
        s.update(msg);
        return s.sign();
    }

    // RSA-PSS(SHA-256) 서명을 검증
    static void verifyRsaPssSha256(PublicKey pub, byte[] msg, byte[] sig) throws Exception {
        Signature s = Signature.getInstance("RSASSA-PSS");
        PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        s.setParameter(pss);
        s.initVerify(pub);
        s.update(msg);
        if (!s.verify(sig)) throw new SignatureException("서버 서명이 올바르지 않습니다.");
    }

    // PKCS#8 형식의 RSA 개인키(PEM 문자열)를 Java PrivateKey로 변환
    static Key loadPrivateKeyPKCS8(String pem) throws Exception {
        byte[] der = parsePem(pem, "PRIVATE KEY");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    // X.509 형식의 RSA 공개키(PEM 문자열)를 Java PublicKey로 변환
    static Key loadPublicKeyX509(String pem) throws Exception {
        byte[] der = parsePem(pem, "PUBLIC KEY");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    // PEM 텍스트에서 BEGIN/END 사이 Base64 본문만 추출해 바이트 배열로 디코딩
    static byte[] parsePem(String pem, String type) {
        if (pem == null) throw new IllegalArgumentException("PEM 누락: " + type);
        String begin = "-----BEGIN " + type + "-----";
        String end   = "-----END " + type + "-----";
        int i = pem.indexOf(begin), j = pem.indexOf(end);
        if (i < 0 || j < 0) throw new IllegalArgumentException(type + " PEM 형식이 올바르지 않습니다.");
        String base64 = pem.substring(i + begin.length(), j).replaceAll("\\s", ""); // 모든 공백 제거
        return Base64.getDecoder().decode(base64);
    }

    // 데모용 JSON 생성기
    static String toJson(Map<String, String> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(e.getKey()).append('"').append(':')
                    .append('"').append(e.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    // 데모용 JSON 파서
    static Map<String, String> parseFlatJson(String json) {
        Map<String, String> map = new HashMap<>();
        String s = json.trim();
        if (s.startsWith("{") && s.endsWith("}")) s = s.substring(1, s.length()-1);
        if (s.isEmpty()) return map;
        for (String part : s.split(",")) {
            String[] kv = part.split(":", 2);
            String k = kv[0].trim().replaceAll("^\"|\"$", "");
            String v = kv[1].trim().replaceAll("^\"|\"$", "");
            map.put(k, v);
        }
        return map;
    }

    // HTTP POST로 JSON을 전송하고, 응답 본문을 문자열로 반환
    static String httpPostJson(String url, String body) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line; while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}