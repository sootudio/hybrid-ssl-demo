package com.example.hybrid_ssl_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import javax.crypto.spec.PSource;
import java.io.InputStream;
import java.io.IOException;

@SpringBootApplication
public class EncryptedApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(EncryptedApiApplication.class, args);
    }

    // 서버 RSA 키쌍
    static final String SERVER_PRIVATE_KEY_PEM = readClasspath("/keys/server_priv_pkcs8.pem");
    // static final String SERVER_PUBLIC_KEY_PEM  = readClasspath("/keys/server_pub_x509.pem"); // 사용하지 않음. 보관용

    // 클라이언트 공개키 (서버가 클라이언트 서명을 검증할 때 사용)
    static final Map<String, String> CLIENT_PUBKEY_REGISTRY = new HashMap<>() {{
        put("client-1", readClasspath("/keys/client_pub_x509.pem"));
    }};

    // 키 경로 읽기
    static String readClasspath(String path) {
        try (InputStream is = EncryptedApiApplication.class.getResourceAsStream(path)) {
            if (is == null) {
                throw new IllegalArgumentException("클래스패스 리소스를 찾을 수 없습니다: " + path);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("리소스 읽기 실패: " + path, e);
        }
    }

    @RestController
    @RequestMapping("/api")
    static class SecureApiController {

        @PostMapping(value = "/secure", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
        public Map<String, Object> secureEndpoint(@RequestBody Map<String, String> body) throws Exception {
            String clientId = required(body, "clientId");
            String ekB64    = required(body, "ek");       // RSA-OAEP로 감싼 (AES키||IV)
            String dataB64  = required(body, "data");     // AES-GCM으로 암호화된 본문
            String sigB64   = required(body, "sig");      // 클라이언트 개인키로 (ek||data)에 서명한 값

            // 클라이언트로부터 받은 암호화 값 출력
            System.out.println("클라이언트로부터 받은 암호화 값: ek=" + ekB64 + ", data=" + dataB64);

            // 키 불러오기
            RSAPrivateKey serverPriv = (RSAPrivateKey) Pem.loadPrivateKeyPKCS8(SERVER_PRIVATE_KEY_PEM);
            RSAPublicKey clientPub   = (RSAPublicKey) Pem.loadPublicKeyX509(CLIENT_PUBKEY_REGISTRY.get(clientId));

            // (ek || data)에 대한 클라이언트 서명 검증
            byte[] ek   = Base64.getDecoder().decode(ekB64);
            byte[] ciph = Base64.getDecoder().decode(dataB64);
            byte[] sig  = Base64.getDecoder().decode(sigB64);

            byte[] signedMsg = ByteBuffer.allocate(ek.length + ciph.length).put(ek).put(ciph).array();
            Signatures.verifyRsaPssSha256(clientPub, signedMsg, sig);

            // ek 풀기 => (AES키 || IV)
            byte[] wrapped = ek;
            byte[] aesIvConcat = Rsa.oaepDecrypt(serverPriv, wrapped);
            // 기대값: AES키 32바이트 + IV 12바이트
            if (aesIvConcat.length != 32 + 12) throw new IllegalStateException("Invalid wrapped length");
            byte[] aesKey = Arrays.copyOfRange(aesIvConcat, 0, 32);
            byte[] ivReq  = Arrays.copyOfRange(aesIvConcat, 32, 44);

            // 요청 복호화(AES-GCM)
            byte[] plainReq = AesGcm.decrypt(aesKey, ivReq, ciph, null);
            String json = new String(plainReq, StandardCharsets.UTF_8);

            // 복호화 결과 출력
            System.out.println("클라이언트로부터 받은 암호화 값 복호화 결과: " + json);

            // 비즈니스 로직: 받은 내용을 echo하고, 서버 시간을 함께 보냄
            String responsePlain = "{" +
                    "\"ok\":true," +
                    "\"serverTime\":\"" + Instant.now().toString() + "\"," +
                    "\"echo\":" + json +
                    "}";

            // 같은 AES 키로 응답 암호화하되, **반드시 새 IV**를 만듭니다.
            byte[] ivRes = AesGcm.randomIv12();
            byte[] resCipher = AesGcm.encrypt(aesKey, ivRes, responsePlain.getBytes(StandardCharsets.UTF_8), null);

            // (resIV || resCipher)에 서버 개인키로 서명(RSA-PSS)
            byte[] toSign = ByteBuffer.allocate(ivRes.length + resCipher.length).put(ivRes).put(resCipher).array();
            byte[] resSig = Signatures.signRsaPssSha256(serverPriv, toSign);

            Map<String, Object> res = new HashMap<>();
            res.put("resIV", Base64.getEncoder().encodeToString(ivRes));
            res.put("data", Base64.getEncoder().encodeToString(resCipher));
            res.put("sig", Base64.getEncoder().encodeToString(resSig));
            return res;
        }

        private static String required(Map<String, String> m, String k) {
            String v = m.get(k);
            if (v == null || v.isEmpty()) throw new IllegalArgumentException("필수 필드 누락: " + k);
            return v;
        }
    }

    // ===== 서버 공용 유틸 =====
    static class Pem {
        // PKCS#8 개인키(PEM)를 읽어서 Key 객체로 변환
        static Key loadPrivateKeyPKCS8(String pem) throws Exception {
            byte[] der = parsePem(pem, "PRIVATE KEY");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("PKCS#8 개인키 형식이 잘못되었습니다.");
            }
        }

        // X.509 공개키(PEM)를 읽어서 Key 객체로 변환
        static Key loadPublicKeyX509(String pem) throws Exception {
            byte[] der = parsePem(pem, "PUBLIC KEY");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        }

        // PEM 텍스트에서 BASE64 본문만 추출
        private static byte[] parsePem(String pem, String type) {
            if (pem == null) throw new IllegalArgumentException(type + " PEM 문자열이 없습니다.");

            String begin = "-----BEGIN " + type + "-----";
            String end   = "-----END " + type + "-----";

            int i = pem.indexOf(begin);
            int j = pem.indexOf(end);
            if (i < 0 || j < 0) throw new IllegalArgumentException(type + " PEM 헤더/푸터가 없습니다.");

            // BEGIN/END 사이의 Base64 본문만 추출 후, 모든 공백 제거
            String base64 = pem.substring(i + begin.length(), j).replaceAll("\\s", "");
            return Base64.getDecoder().decode(base64);
        }
    }

    static class Rsa {
        // 서버 공개키로 메시지 암호화(OAEP: SHA-256)
        static byte[] oaepEncrypt(RSAPublicKey pub, byte[] msg) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            c.init(Cipher.ENCRYPT_MODE, pub, oaep);
            return c.doFinal(msg);
        }

        // 서버 개인키로 OAEP 암호문 복호화
        static byte[] oaepDecrypt(RSAPrivateKey priv, byte[] ct) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaep = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
            c.init(Cipher.DECRYPT_MODE, priv, oaep);
            return c.doFinal(ct);
        }
    }

    static class AesGcm {
        // 12바이트 IV를 무작위로 생성
        static byte[] randomIv12() {
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            return iv;
        }

        // AES-GCM으로 암호화 (태그 길이 128비트)
        static byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            SecretKey sk = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, sk, spec);
            if (aad != null) cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        }

        // AES-GCM으로 복호화
        static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            SecretKey sk = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, sk, spec);
            if (aad != null) cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        }
    }

    static class Signatures {
        // RSA-PSS(SHA-256)로 서명
        static byte[] signRsaPssSha256(PrivateKey priv, byte[] msg) throws Exception {
            Signature s = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
            s.setParameter(pss);
            s.initSign(priv);
            s.update(msg);
            return s.sign();
        }

        // RSA-PSS(SHA-256) 서명 검증
        static void verifyRsaPssSha256(PublicKey pub, byte[] msg, byte[] sig) throws Exception {
            Signature s = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec pss = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
            s.setParameter(pss);
            s.initVerify(pub);
            s.update(msg);
            if (!s.verify(sig)) throw new SignatureException("서명 검증 실패");
        }
    }
}