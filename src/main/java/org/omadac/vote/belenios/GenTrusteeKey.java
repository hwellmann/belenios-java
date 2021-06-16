package org.omadac.vote.belenios;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.TrusteeKeyPair;
import org.omadac.vote.belenios.model.TrusteePublicKey;

import ch.openchvote.algorithms.general.GenRandomInteger;

public class GenTrusteeKey {

    public static TrusteeKeyPair genKeyPair(Group group) {
        var privateKey = GenRandomInteger.run(group.q());
        var publicKey = group.g().modPow(privateKey, group.p());
        var id = buildId(publicKey);

        var proof = buildProofOfKnowledge(group, publicKey, privateKey);

        var trusteePublicKey = TrusteePublicKey.builder()
            .id(id)
            .publicKey(publicKey)
            .pok(proof)
            .build();

        return TrusteeKeyPair.builder()
            .privateKey(privateKey)
            .trusteePublicKey(trusteePublicKey)
            .build();
    }

    public static Proof buildProofOfKnowledge(Group group, BigInteger publicKey, BigInteger privateKey) {
        var w = GenRandomInteger.run(group.q());
        var a = group.g().modPow(w, group.p());
        var challenge = buildChallenge(group.q(), publicKey, a);
        var response = buildResponse(group.q(), privateKey, challenge, w);
        return Proof.builder()
            .challenge(challenge)
            .response(response).build();
    }

    private static BigInteger buildChallenge(BigInteger q, BigInteger publicKey, BigInteger a) {
        var message = String.format("pok|%s|%s", publicKey, a);
        return ModularChecksum.checksum(message, q);
    }

    private static String buildId(BigInteger publicKey) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var encodedhash = digest.digest(publicKey.toString().getBytes(StandardCharsets.UTF_8));

            return Hex.bytesToHex(encodedhash).substring(0, 8);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalArgumentException(exc);
        }
    }

    private static BigInteger buildResponse(BigInteger q, BigInteger privateKey, BigInteger challenge, BigInteger w) {
        return privateKey.multiply(challenge).add(w).mod(q);
    }

    public static boolean isValid(Group group, TrusteePublicKey trusteePublicKey) {
        var c1 = group.g().modPow(trusteePublicKey.pok().response(), group.p());
        var c2 = trusteePublicKey.publicKey()
            .modPow(trusteePublicKey.pok().challenge(), group.p())
            .modInverse(group.p());
        var a = c1.multiply(c2).mod(group.p());
        var challenge = buildChallenge(group.q(), trusteePublicKey.publicKey(), a);
        return challenge.equals(trusteePublicKey.pok().challenge());
    }

}
