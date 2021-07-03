package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.joining;
import static org.omadac.vote.belenios.algo.ModularChecksum.checksum;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.omadac.vote.belenios.model.Answer;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.Signature;
import org.omadac.vote.belenios.model.WrappedPublicKey;

public class VerifyBallot {

    public static boolean verifyBallot(Ballot ballot, Election election) {
        var publicCred = ballot.signature().publicKey();
        var y = election.publicKey();
        for (int i = 0; i < election.questions().size(); i++) {
            var question = election.questions().get(i);
            var blankAllowed = question.blankAnswerAllowed();
            var answer = ballot.answers().get(i);
            for (int j = 0; j < answer.choices().size(); j++) {
                var choice = answer.choices().get(j);
                var proofs = answer.individualProofs().get(j);
                var isCorrect = verifyIntervalProof(y, publicCred, choice, 0, 1, proofs);
                if (!isCorrect) {
                    return false;
                }
            }

            if (blankAllowed) {
                var isCorrect = verifyBlankProof(answer, publicCred, y)
                    && verifyOverallProof(answer, publicCred, y);

                if (!isCorrect) {
                    return false;
                }
            } else {
                var ctSigma = answer.choices().stream()
                    .reduce(Ciphertext.NEUTRAL, (left, right) -> left.combine(right, y.group().p()));
                if (!verifyIntervalProof(y, publicCred, ctSigma, question.min(), question.max(),
                    answer.overallProof())) {
                    return false;
                }
            }
        }

        return verifySignature(ballot.signature(), ballot.answers(), y.group());
    }

    public static boolean verifyIntervalProof(WrappedPublicKey publicKey, BigInteger publicCred,
        Ciphertext ct, int min, int max, List<Proof> proofs) {
        var group = publicKey.group();
        var j = min;
        List<Ciphertext> abs = new ArrayList<>();
        for (Proof proof: proofs) {
            var challenge = proof.challenge();
            var response = proof.response();
            var aNum = group.g().modPow(response, group.p());
            var aDenom = ct.alpha().modPow(challenge, group.p());
            var a = aNum.multiply(aDenom.modInverse(group.p())).mod(group.p());

            var bNum = publicKey.y().modPow(response, group.p());
            var bDenom = ct.beta().multiply(group.g().modInverse(group.p()).modPow(BigInteger.valueOf(j), group.p()))
                .modPow(challenge, group.p());
            var b = bNum.multiply(bDenom.modInverse(group.p())).mod(group.p());

            var ab = Ciphertext.builder().alpha(a).beta(b).build();
            abs.add(ab);
            j++;
        }

        var suffix = abs.stream()
            .map(ab -> (ab.alpha() + "," + ab.beta()))
            .collect(joining(","));
        var message = String.format("prove|%s|%s,%s|%s", publicCred.toString(),
            ct.alpha().toString(), ct.beta().toString(), suffix);
        var checksum = checksum(message, group.q());

        var challengeSum = proofs.stream().map(Proof::challenge)
            .reduce(BigInteger.ZERO, BigInteger::add)
            .mod(group.q());
        return checksum.equals(challengeSum);
    }

    public static boolean verifyVote(BigInteger alpha, BigInteger beta, BigInteger challenge0, BigInteger response0,
        BigInteger challenge1, BigInteger response1, BigInteger publicCred, WrappedPublicKey wrappedPublicKey) {
        var group = wrappedPublicKey.group();
        var a0Num = group.g().modPow(response0, group.p());
        var a0Denom = alpha.modPow(challenge0, group.p());
        var a0 = a0Num.multiply(a0Denom.modInverse(group.p())).mod(group.p());

        var b0Num = wrappedPublicKey.y().modPow(response0, group.p());
        var b0Denom = beta.modPow(challenge0, group.p());
        var b0 = b0Num.multiply(b0Denom.modInverse(group.p())).mod(group.p());

        var a1Num = group.g().modPow(response1, group.p());
        var a1Denom = alpha.modPow(challenge1, group.p());
        var a1 = a1Num.multiply(a1Denom.modInverse(group.p())).mod(group.p());

        var b1Num = wrappedPublicKey.y().modPow(response1, group.p());
        var b1Denom = beta.multiply(group.g().modInverse(group.p())).modPow(challenge1, group.p());
        var b1 = b1Num.multiply(b1Denom.modInverse(group.p())).mod(group.p());

        var challenges = challenge0.add(challenge1).mod(group.q());

        String message = String.format("prove|%s|%s,%s|%s,%s,%s,%s", publicCred,
            alpha, beta,
            a0, b0, a1, b1);

        var checksum = checksum(message, group.q());

        return challenges.equals(checksum);
    }

    public static boolean verifyBlankProof(Answer answer, BigInteger publicCred, WrappedPublicKey publicKey) {
        var ct0 = answer.choices().get(0);
        var ctSigma = answer.choices().stream().skip(1)
            .reduce(Ciphertext.NEUTRAL, (left, right) -> left.combine(right, publicKey.group().p()));
        var alpha0 = ct0.alpha();
        var beta0 = ct0.beta();
        var alphaSigma = ctSigma.alpha();
        var betaSigma = ctSigma.beta();
        var challenge0 = answer.blankProof().get(0).challenge();
        var response0 = answer.blankProof().get(0).response();
        var challengeSigma = answer.blankProof().get(1).challenge();
        var responseSigma = answer.blankProof().get(1).response();

        var prefix = Stream
            .of(publicKey.group().g(), publicKey.y(), ct0.alpha(), ct0.beta(), ctSigma.alpha(), ctSigma.beta())
            .map(BigInteger::toString)
            .collect(joining(","));

        return verifyBlankProof(alpha0, beta0, alphaSigma, betaSigma,
            challenge0, response0, challengeSigma, responseSigma,
            prefix, publicCred, publicKey);
    }

    public static boolean verifyBlankProof(BigInteger alpha0, BigInteger beta0, BigInteger alphaSigma,
        BigInteger betaSigma, BigInteger challenge0, BigInteger response0, BigInteger challengeSigma,
        BigInteger responseSigma, String prefix, BigInteger publicCred, WrappedPublicKey wrappedPublicKey) {

        var group = wrappedPublicKey.group();
        var a0 = group.g().modPow(response0, group.p()).multiply(alpha0.modPow(challenge0, group.p())).mod(group.p());
        var b0 = wrappedPublicKey.y().modPow(response0, group.p()).multiply(beta0.modPow(challenge0, group.p()))
            .mod(group.p());
        var aSigma = group.g().modPow(responseSigma, group.p())
            .multiply(alphaSigma.modPow(challengeSigma, group.p()))
            .mod(group.p());
        var bSigma = wrappedPublicKey.y().modPow(responseSigma, group.p())
            .multiply(betaSigma.modPow(challengeSigma, group.p()))
            .mod(group.p());

        String message = String.format("bproof0|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, aSigma, bSigma);
        var checksum = checksum(message, group.q());

        var challenges = challenge0.add(challengeSigma).mod(group.q());
        return challenges.equals(checksum);
    }

    public static boolean verifyOverallProof(Answer answer, BigInteger publicCred, WrappedPublicKey publicKey) {
        var ct0 = answer.choices().get(0);
        var ctSigma = answer.choices().stream().skip(1)
            .reduce(Ciphertext.NEUTRAL, (left, right) -> left.combine(right, publicKey.group().p()));
        var alpha0 = ct0.alpha();
        var beta0 = ct0.beta();
        var alphaSigma = ctSigma.alpha();
        var betaSigma = ctSigma.beta();
        var challenge0 = answer.overallProof().get(0).challenge();
        var response0 = answer.overallProof().get(0).response();
        var challenge1 = answer.overallProof().get(1).challenge();
        var response1 = answer.overallProof().get(1).response();

        var prefix = Stream
            .of(publicKey.group().g(), publicKey.y(), ct0.alpha(), ct0.beta(), ctSigma.alpha(), ctSigma.beta())
            .map(BigInteger::toString)
            .collect(joining(","));

        return verifyOverallProof(alpha0, beta0, alphaSigma, betaSigma,
            challenge0, response0, challenge1, response1,
            prefix, publicCred, publicKey);
    }

    public static boolean verifyOverallProof(BigInteger alpha0, BigInteger beta0, BigInteger alphaSigma,
        BigInteger betaSigma, BigInteger challenge0, BigInteger response0, BigInteger challenge1,
        BigInteger response1, String prefix, BigInteger publicCred, WrappedPublicKey publicKey) {

        var group = publicKey.group();
        var a0 = group.g().modPow(response0, group.p()).multiply(alpha0.modPow(challenge0, group.p())).mod(group.p());
        var b0 = publicKey.y().modPow(response0, group.p())
            .multiply(beta0.multiply(group.g().modInverse(group.p()))
                .modPow(challenge0, group.p()))
            .mod(group.p());
        var aSigma = group.g().modPow(response1, group.p())
            .multiply(alphaSigma.modPow(challenge1, group.p()))
            .mod(group.p());
        var bSigma = publicKey.y().modPow(response1, group.p())
            .multiply(betaSigma.multiply(group.g().modInverse(group.p()))
                .modPow(challenge1, group.p()))
            .mod(group.p());

        String message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, aSigma, bSigma);
        var checksum = checksum(message, group.q());

        var challenges = challenge0.add(challenge1).mod(group.q());
        return challenges.equals(checksum);
    }

    public static boolean verifySignature(Ballot ballot, Election election) {
        return verifySignature(ballot.signature(), ballot.answers(), election.publicKey().group());
    }

    public static boolean verifySignature(Signature signature, List<Answer> answers, Group group) {
        var a = group.g().modPow(signature.response(), group.p())
            .multiply(signature.publicKey().modPow(signature.challenge(), group.p())).mod(group.p());

        var text = answers.stream().flatMap(answer -> answer.choices().stream())
            .map(c -> c.alpha() + "," + c.beta())
            .collect(joining(","));

        var message = String.format("sig|%s|%s|%s", signature.publicKey(), a, text);
        var checksum = checksum(message, group.q());
        return signature.challenge().equals(checksum);
    }
}
