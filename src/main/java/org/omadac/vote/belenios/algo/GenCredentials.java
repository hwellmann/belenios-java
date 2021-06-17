package org.omadac.vote.belenios.algo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Group;

import ch.openchvote.algorithms.general.GenRandomInteger;

public class GenCredentials {

    public static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static final BigInteger N58 = new BigInteger("58");
    public static final BigInteger N53 = new BigInteger("53");

    public static final int TOKEN_LENGTH = 14;
    public static final int RAW_CREDENTIAL_LENGTH = TOKEN_LENGTH + 1;

    public static boolean isValid(String privateCred) {
        var checksum = checksum(privateCred);
        var lastChar = privateCred.charAt(privateCred.length() - 1);
        return lastChar == BASE58.charAt(checksum);
    }

    private static int checksum(String privateCred) {
        var value = toInteger(privateCred);
        var checksum = N53.subtract(value.mod(N53)).intValue();
        return checksum;
    }

    public static BigInteger toInteger(String privateCred) {
        var rawCred = privateCred.replaceAll("-", "");
        if (rawCred.length() != RAW_CREDENTIAL_LENGTH) {
            throw new IllegalArgumentException(privateCred);
        }

        var value = BigInteger.ZERO;
        for (int i = 0; i < RAW_CREDENTIAL_LENGTH - 1; i++) {
            char digit = rawCred.charAt(i);
            int index = BASE58.indexOf(digit);
            value = value.multiply(N58).add(BigInteger.valueOf(index));
        }
        return value;
    }

    public static BigInteger toSecretKey(String privateCred, String uuid, Group group) {
        try {
            var factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            var spec = new PBEKeySpec(privateCred
                //.replaceAll("-", "")
                .toCharArray(),
                uuid.getBytes(StandardCharsets.UTF_8), 1000, 256);
            var rawSecret = new BigInteger(1, factory.generateSecret(spec).getEncoded());
            return rawSecret.mod(group.q());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException exc) {
            throw new IllegalArgumentException(exc);
        }
    }

    public static BigInteger derive(String privateCred, String uuid, Group group) {
        var secretKey = toSecretKey(privateCred, uuid, group);

        return group.g().modPow(secretKey, group.p());

    }

    public static String generateToken() {
        String raw = "";
        for (int i = 0; i < TOKEN_LENGTH; i++) {
            int index = GenRandomInteger.run(0, BASE58.length() - 1);
            char c = BASE58.charAt(index);
            raw += c;
        }
        return raw;
    }

    public static Credentials generate(String uuid, Group group) {
        String raw = generateToken();

        String temp = raw + "1";
        var checksum = checksum(temp);
        var lastChar = BASE58.charAt(checksum);
        raw += lastChar;

        String privateCred = "";
        for (int i = 0; i < RAW_CREDENTIAL_LENGTH; i++) {
            if (i > 0 && (i % 3 == 0)) {
                privateCred += "-";
            }
            privateCred += raw.charAt(i);
        }

        BigInteger publicCred = derive(privateCred, uuid, group);

        return Credentials.builder()
            .privateCred(privateCred)
            .publicCred(publicCred)
            .build();
    }
}
