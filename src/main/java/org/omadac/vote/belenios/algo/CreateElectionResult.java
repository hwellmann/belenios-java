package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.PartialDecryption;
import org.omadac.vote.belenios.model.Result;

public class CreateElectionResult {

    public static Result createResult(Election election, int numTallied,
        List<List<Ciphertext>> encryptedTally, List<PartialDecryption> partialDecryptions) {
        var g = election.publicKey().group().g();
        var p = election.publicKey().group().p();
        Map<BigInteger, Integer> logTable = createLogTable(numTallied, g, p);

        List<List<Integer>> result = new ArrayList<>();
        for (int i = 0; i < encryptedTally.size(); i++) {
            List<Ciphertext> tallyItem = encryptedTally.get(i);
            List<Integer> resultItems = new ArrayList<>();
            for (int j = 0; j < tallyItem.size(); j++) {
                var ct = tallyItem.get(j);
                var factor = factor(i, j, partialDecryptions, p);

                var exp = ct.beta().multiply(factor.modInverse(p)).mod(p);
                var resultValue = logTable.get(exp);
                resultItems.add(resultValue);
            }
            result.add(resultItems);
        }

        return Result.builder()
            .numTallied(numTallied)
            .encryptedTally(encryptedTally)
            .partialDecryptions(partialDecryptions)
            .result(result)
            .build();
    }

    private static BigInteger factor(int i, int j, List<PartialDecryption> partialDecryptions, BigInteger p) {
        BigInteger factor = BigInteger.ONE;
        for (PartialDecryption pd: partialDecryptions) {
            factor = factor.multiply(pd.decryptionFactors().get(i).get(j)).mod(p);
        }
        return factor;
    }

    private static Map<BigInteger, Integer> createLogTable(int numTallied, BigInteger g, BigInteger p) {
        BigInteger value = BigInteger.ONE;
        Map<BigInteger, Integer> logTable = new HashMap<>();
        logTable.put(value, 0);
        for (int exp = 1; exp <= numTallied; exp++) {
            value = value.multiply(g).mod(p);
            logTable.put(value, exp);
        }
        return logTable;
    }

    public static <T, U> List<List<U>> transform(List<List<T>> listOfLists, Function<T, U> function) {
        return listOfLists.stream().map(list -> transformItems(list, function)).collect(toList());
    }

    public static <T, U> List<U> transformItems(List<T> list, Function<T, U> function) {
        return list.stream().map(function).collect(toList());
    }

}
