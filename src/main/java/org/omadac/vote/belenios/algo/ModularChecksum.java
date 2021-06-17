package org.omadac.vote.belenios.algo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ModularChecksum {

    public static BigInteger checksum(String message, BigInteger modulus) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var encodedhash = digest.digest(message.toString().getBytes(StandardCharsets.UTF_8));
            var checksum = new BigInteger(1, encodedhash).mod(modulus);
            return checksum;
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalArgumentException(exc);
        }
    }
}
