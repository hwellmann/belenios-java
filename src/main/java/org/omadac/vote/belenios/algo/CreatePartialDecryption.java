package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.toList;
import static org.omadac.vote.belenios.algo.ModularChecksum.checksum;

import java.math.BigInteger;
import java.util.List;
import java.util.function.Function;

import org.graalvm.collections.Pair;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.PartialDecryption;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.TrusteeKeyPair;

public class CreatePartialDecryption {

    public static PartialDecryption decrypt(Election election, TrusteeKeyPair keyPair,
        List<List<Ciphertext>> encryptedTally) {
        var decryptionFactorsAndProofs = transform(encryptedTally,
            ct -> decryptionFactorAndProof(ct, election, keyPair));
        List<List<BigInteger>> decryptionFactors = transform(decryptionFactorsAndProofs, Pair::getLeft);
        List<List<Proof>> proofs = transform(decryptionFactorsAndProofs, Pair::getRight);
        return PartialDecryption.builder()
            .decryptionFactors(decryptionFactors)
            .decryptionProofs(proofs)
            .build();
    }

    public static <T, U> List<List<U>> transform(List<List<T>> listOfLists, Function<T, U> function) {
        return listOfLists.stream().map(list -> transformItems(list, function)).collect(toList());
    }

    public static <T, U> List<U> transformItems(List<T> list, Function<T, U> function) {
        return list.stream().map(function).collect(toList());
    }

    public static Pair<BigInteger, Proof> decryptionFactorAndProof(Ciphertext ct, Election election,
        TrusteeKeyPair keyPair) {
        var x = keyPair.privateKey();
        var g = election.publicKey().group().g();
        var p = election.publicKey().group().p();
        var q = election.publicKey().group().q();
        var factor = ct.alpha().modPow(x, p);

        var w = GenRandomInteger.run(q);
        var a = g.modPow(w, p);
        var b = ct.alpha().modPow(w, p);

        var message = String.format("decrypt|%s|%s,%s", keyPair.trusteePublicKey().publicKey(), a, b);
        var challenge = checksum(message, q);
        var response = challenge.multiply(x).add(w).mod(p);
        var proof = Proof.builder().challenge(challenge).response(response).build();
        return Pair.create(factor, proof);
    }

    public static boolean verify(Election election, TrusteeKeyPair keyPair,
        List<List<Ciphertext>> encryptedTally, PartialDecryption decryption) {

        var y = keyPair.trusteePublicKey().publicKey();
        var g = election.publicKey().group().g();
        var p = election.publicKey().group().p();
        var q = election.publicKey().group().q();

        for (int i = 0; i < encryptedTally.size(); i++) {
            List<Ciphertext> tallyItem = encryptedTally.get(i);
            List<Proof> proofs = decryption.decryptionProofs().get(i);
            List<BigInteger> factors = decryption.decryptionFactors().get(i);
            for (int j = 0; j < tallyItem.size(); j++) {
                Ciphertext ct = tallyItem.get(j);
                Proof proof = proofs.get(j);
                BigInteger factor = factors.get(j);

                var a = g.modPow(proof.response(), p)
                    .multiply(y.modPow(proof.challenge(), p).modInverse(p))
                    .mod(p);

                var b = ct.alpha().modPow(proof.response(), p)
                    .multiply(factor.modPow(proof.challenge(), p).modInverse(p))
                    .mod(p);

                var message = String.format("decrypt|%s|%s,%s", y, a, b);
                var checksum = checksum(message, q);
                if (!checksum.equals(proof.challenge())) {
                    return false;
                }
            }
        }

        return true;
    }
}
