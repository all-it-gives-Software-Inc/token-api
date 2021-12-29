package org.token.service;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.enterprise.context.ApplicationScoped;
import java.nio.file.AccessDeniedException;

@Slf4j
@ApplicationScoped
public class TokenService {

    @SneakyThrows
    private String decryptToken(String encryptedToken) {
        log.info("Decrypting token");

        JWEObject jweObject = JWEObject.parse(encryptedToken);

        jweObject.getPayload();

        String privateKey = "qxBEEQv7E8aviX1KUcdOiF5ve5COUPAr";
        DirectDecrypter directDecrypter = new DirectDecrypter(privateKey.getBytes());

        jweObject.decrypt(directDecrypter);

        return jweObject.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public JWTClaimsSet getPayloadToken(String token) {
        String decryptToken = decryptToken(token);
        JWT parse = JWTParser.parse(decryptToken);
        JWTClaimsSet jwtClaimsSet = parse.getJWTClaimsSet();

        return jwtClaimsSet;

    }

    @SneakyThrows
    public void validateTokenSignature(String signedToken) {
        log.info("Starting method to validate token signature...");

        SignedJWT signedJWT = SignedJWT.parse(signedToken);

        log.info("Token Parsed! Retrieving public key from signed token");

        RSAKey publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());

        log.info("Public key retrieved, validating signature. . . ");

        if (!signedJWT.verify(new RSASSAVerifier(publicKey))) {
            throw new AccessDeniedException("Invalid token signature!");
        }

        log.info("The token has a valid signature");
    }
}

