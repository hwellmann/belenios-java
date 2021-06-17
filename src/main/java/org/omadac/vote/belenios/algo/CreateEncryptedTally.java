package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.toList;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Question;

public class CreateEncryptedTally {

    public static List<List<Ciphertext>> tally(Election election, Stream<Ballot> ballots) {
        List<List<Ciphertext>> neutral = neutral(election);
        BigInteger p = election.publicKey().group().p();
        return ballots.map(b -> extractCiphertexts(b))
            .reduce(neutral, (left, right) -> combine(left, right, p));
    }

    public static List<List<Ciphertext>> neutral(Election election) {
        return election.questions().stream().map(q -> neutral(q)).collect(toList());
    }

    public static List<Ciphertext> neutral(Question q) {
        int numAnswers = q.answers().size();
        if (q.blankAnswerAllowed()) {
            numAnswers++;
        }

        return IntStream.range(0, numAnswers).mapToObj(i -> Ciphertext.NEUTRAL).collect(toList());
    }

    public static List<List<Ciphertext>> extractCiphertexts(Ballot ballot) {
        return ballot.answers().stream().map(a -> a.choices()).collect(toList());
    }

    public static List<List<Ciphertext>> combine(List<List<Ciphertext>> left, List<List<Ciphertext>> right,
        BigInteger p) {
        if (left.size() != right.size()) {
            throw new IllegalArgumentException("operand size mismatch");
        }
        List<List<Ciphertext>> result = new ArrayList<>();
        for (int i = 0; i < left.size(); i++) {
            result.add(combineList(left.get(i), right.get(i), p));
        }
        return result;
    }

    public static List<Ciphertext> combineList(List<Ciphertext> left, List<Ciphertext> right, BigInteger p) {
        if (left.size() != right.size()) {
            throw new IllegalArgumentException("operand size mismatch");
        }
        List<Ciphertext> result = new ArrayList<>();
        for (int i = 0; i < left.size(); i++) {
            result.add(combine(left.get(i), right.get(i), p));
        }
        return result;
    }

    public static Ciphertext combine(Ciphertext left, Ciphertext right, BigInteger p) {
        var alpha = left.alpha().multiply(right.alpha()).mod(p);
        var beta = left.beta().multiply(right.beta()).mod(p);
        return Ciphertext.builder().alpha(alpha).beta(beta).build();
    }
}
