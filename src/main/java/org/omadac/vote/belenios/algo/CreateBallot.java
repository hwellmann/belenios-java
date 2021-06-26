package org.omadac.vote.belenios.algo;

import static java.util.stream.Collectors.toList;
import static org.omadac.vote.belenios.algo.ModularChecksum.checksum;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.omadac.vote.belenios.model.Answer;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ballot.Builder;
import org.omadac.vote.belenios.model.CiphertextAndSecret;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.Question;
import org.omadac.vote.belenios.model.Signature;
import org.omadac.vote.belenios.model.WrappedPublicKey;

import ch.openchvote.algorithms.general.GenRandomInteger;
import ch.openchvote.util.tuples.Pair;

public class CreateBallot {

    public static Ballot createBallot(Election election, Credentials credentials,
        List<List<Integer>> rawVotes) {
        if (election.questions().size() != rawVotes.size()) {
            throw new IllegalArgumentException("Incorrect number of answers");
        }
        Builder builder = Ballot.builder();
        List<Answer> answers = new ArrayList<>();
        for (int i = 0; i < rawVotes.size(); i++) {
            var question = election.questions().get(i);
            var rawVote = rawVotes.get(i);
            var answer = createAnswer(election.publicKey(), credentials.publicCred(), question, rawVote);
            answers.add(answer);
            builder.addAnswer(answer);
        }
        Signature signature = createSignature(answers, credentials, election);

        return builder
            .electionUuid(election.uuid())
            .electionHash(createElectionHash(election))
            .signature(signature)
            .build();
    }

    private static Answer createAnswer(WrappedPublicKey publicKey, BigInteger publicCred, Question question,
        List<Integer> rawVote) {
        validateRawVote(question, rawVote);

        var choicesAndProofs = rawVote.stream().map(vote -> createCiphertext(publicKey, publicCred, vote))
            .collect(toList());
        var choicesAndSecrets = choicesAndProofs.stream().map(Pair::getFirst).collect(toList());
        var choices = choicesAndProofs.stream().map(Pair::getFirst).map(CiphertextAndSecret::ciphertext)
            .collect(toList());
        var proofs = choicesAndProofs.stream().map(Pair::getSecond).collect(toList());

        var ct0 = choicesAndSecrets.get(0);
        var ctSigma = sum(choicesAndSecrets, publicKey.group().p());

        var prefix = Stream
            .of(publicKey.group().g(), publicKey.y(), ct0.alpha(), ct0.beta(), ctSigma.alpha(), ctSigma.beta())
            .map(BigInteger::toString)
            .collect(Collectors.joining(","));

        var builder = Answer.builder()
            .choices(choices)
            .individualProofs(proofs)
            .overallProof(createOverallProof(publicKey, publicCred, ct0, ctSigma, rawVote.get(0), prefix));

        if (question.blankAnswerAllowed()) {
            builder.blankProof(createBlankProof(publicKey, publicCred, ct0, ctSigma, rawVote.get(0), prefix));
        }
        return builder.build();
    }

    private static Pair<CiphertextAndSecret, List<Proof>> createCiphertext(WrappedPublicKey publicKey,
        BigInteger publicCred,
        int rawVote) {
        var group = publicKey.group();

        var r = GenRandomInteger.run(group.q());
        var alpha = group.g().modPow(r, group.p());
        var beta = publicKey.y().modPow(r, group.p())
            .multiply(group.g().modPow(BigInteger.valueOf(rawVote), group.p()))
            .mod(group.p());
        var ct = CiphertextAndSecret.builder().alpha(alpha).beta(beta).r(r).build();
        List<Proof> proofs;
        if (rawVote == 0) {
            proofs = createProofOfZero(publicKey, publicCred, ct);
        } else {
            proofs = createProofOfOne(publicKey, publicCred, ct);
        }
        return new Pair<>(ct, proofs);
    }

    private static CiphertextAndSecret sum(List<CiphertextAndSecret> cts, BigInteger p) {
        var alpha = BigInteger.ONE;
        var beta = BigInteger.ONE;
        var r = BigInteger.ZERO;
        for (int i = 1; i < cts.size(); i++) {
            alpha = alpha.multiply(cts.get(i).alpha()).mod(p);
            beta = beta.multiply(cts.get(i).beta()).mod(p);
            r = r.add(cts.get(i).r()).mod(p);
        }
        return CiphertextAndSecret.builder()
            .alpha(alpha)
            .beta(beta)
            .r(r)
            .build();
    }

    private static void validateRawVote(Question question, List<Integer> rawVote) {
        boolean isBlank = question.blankAnswerAllowed() && rawVote.get(0).equals(1);
        int sum = rawVote.stream().reduce(0, Integer::sum);
        if (isBlank && sum != 1) {
            throw new IllegalArgumentException("Blank vote must not contain non-zero answers");
        }
        if (!isBlank) {
            if (sum < question.min()) {
                throw new IllegalArgumentException("Vote contains less than " + question.min() + " answers");
            }
            if (sum > question.max()) {
                throw new IllegalArgumentException("Vote contains more than " + question.max() + " answers");
            }
        }
    }

    private static List<Proof> createProofOfZero(WrappedPublicKey publicKey, BigInteger publicCred,
        CiphertextAndSecret ct) {
        var group = publicKey.group();

        var w = GenRandomInteger.run(group.q());
        var a0 = group.g().modPow(w, group.p());
        var b0 = publicKey.y().modPow(w, group.p());

        var challenge1 = GenRandomInteger.run(group.q());
        var response1 = GenRandomInteger.run(group.q());

        var a1Num = group.g().modPow(response1, group.p());
        var a1Denom = ct.alpha().modPow(challenge1, group.p());
        var a1 = a1Num.multiply(a1Denom.modInverse(group.p())).mod(group.p());

        var b1Num = publicKey.y().modPow(response1, group.p());
        var b1Denom = ct.beta().multiply(group.g().modInverse(group.p())).modPow(challenge1, group.p());
        var b1 = b1Num.multiply(b1Denom.modInverse(group.p())).mod(group.p());

        var message = String.format("prove|%s|%s,%s|%s,%s,%s,%s", publicCred.toString(),
            ct.alpha().toString(), ct.beta().toString(),
            a0.toString(), b0.toString(), a1.toString(), b1.toString());

        var checksum = checksum(message, group.q());

        var challenge0 = checksum.subtract(challenge1).mod(group.q());
        var response0 = challenge0.multiply(ct.r()).add(w).mod(group.q());

        var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
        var proof1 = Proof.builder().challenge(challenge1).response(response1).build();
        return List.of(proof0, proof1);
    }

    private static List<Proof> createProofOfOne(WrappedPublicKey publicKey, BigInteger publicCred,
        CiphertextAndSecret ct) {
        var group = publicKey.group();

        var challenge0 = GenRandomInteger.run(group.q());
        var response0 = GenRandomInteger.run(group.q());

        var a0Num = group.g().modPow(response0, group.p());
        var a0Denom = ct.alpha().modPow(challenge0, group.p());
        var a0 = a0Num.multiply(a0Denom.modInverse(group.p())).mod(group.p());

        var b0Num = publicKey.y().modPow(response0, group.p());
        var b0Denom = ct.beta().modPow(challenge0, group.p());
        var b0 = b0Num.multiply(b0Denom.modInverse(group.p())).mod(group.p());

        var w = GenRandomInteger.run(group.q());
        var a1 = group.g().modPow(w, group.p());
        var b1 = publicKey.y().modPow(w, group.p());

        var message = String.format("prove|%s|%s,%s|%s,%s,%s,%s",
            publicCred, ct.alpha(), ct.beta(), a0, b0, a1, b1);

        var checksum = checksum(message, group.q());

        var challenge1 = checksum.subtract(challenge0).mod(group.q());
        var response1 = challenge1.multiply(ct.r()).add(w).mod(group.q());

        var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
        var proof1 = Proof.builder().challenge(challenge1).response(response1).build();
        return List.of(proof0, proof1);
    }

    private static List<Proof> createBlankProof(WrappedPublicKey publicKey, BigInteger publicCred,
        CiphertextAndSecret ct0, CiphertextAndSecret ctSigma,
        int isBlank, String P) {
        var group = publicKey.group();

        if (isBlank == 0) {
            var challengeSigma = GenRandomInteger.run(group.q());
            var responseSigma = GenRandomInteger.run(group.q());

            var aSigma = group.g().modPow(responseSigma, group.p())
                .multiply(ctSigma.alpha().modPow(challengeSigma, group.p())).mod(group.p());
            var bSigma = publicKey.y().modPow(responseSigma, group.p())
                .multiply(ctSigma.beta().modPow(challengeSigma, group.p())).mod(group.p());

            var w = GenRandomInteger.run(group.q());
            var a0 = group.g().modPow(w, group.p());
            var b0 = publicKey.y().modPow(w, group.p());

            String message = String.format("bproof0|%s|%s|%s,%s,%s,%s", publicCred, P, a0, b0, aSigma, bSigma);
            var checksum = checksum(message, group.q());

            var challenge0 = checksum.subtract(challengeSigma).mod(group.q());
            var response0 = w.subtract(ct0.r().multiply(challenge0)).mod(group.q());

            var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
            var proofSigma = Proof.builder().challenge(challengeSigma).response(responseSigma).build();
            return List.of(proof0, proofSigma);
        } else {
            var challenge0 = GenRandomInteger.run(group.q());
            var response0 = GenRandomInteger.run(group.q());

            var a0 = group.g().modPow(response0, group.p())
                .multiply(ct0.alpha().modPow(challenge0, group.p())).mod(group.p());
            var b0 = publicKey.y().modPow(response0, group.p())
                .multiply(ct0.beta().modPow(challenge0, group.p())).mod(group.p());

            var w = GenRandomInteger.run(group.q());
            var aSigma = group.g().modPow(w, group.p());
            var bSigma = publicKey.y().modPow(w, group.p());

            String message = String.format("bproof0|%s|%s|%s,%s,%s,%s", publicCred, P, a0, b0, aSigma, bSigma);
            var checksum = checksum(message, group.q());

            var challengeSigma = checksum.subtract(challenge0).mod(group.q());
            var responseSigma = w.subtract(ctSigma.r().multiply(challengeSigma)).mod(group.q());

            var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
            var proofSigma = Proof.builder().challenge(challengeSigma).response(responseSigma).build();
            return List.of(proof0, proofSigma);
        }
    }

    private static List<Proof> createOverallProof(WrappedPublicKey publicKey, BigInteger publicCred,
        CiphertextAndSecret ct0, CiphertextAndSecret ctSigma,
        int isBlank, String prefix) {
        var group = publicKey.group();

        if (isBlank == 0) {
            var challenge0 = GenRandomInteger.run(group.q());
            var response0 = GenRandomInteger.run(group.q());

            var a0 = group.g().modPow(response0, group.p())
                .multiply(ct0.alpha().modPow(challenge0, group.p())).mod(group.p());
            var b0 = publicKey.y().modPow(response0, group.p())
                .multiply(ct0.beta().multiply(group.g().modInverse(group.p()))
                    .modPow(challenge0, group.p()))
                .mod(group.p());
            var w = GenRandomInteger.run(group.q());
            var a1 = group.g().modPow(w, group.p());
            var b1 = publicKey.y().modPow(w, group.p());

            String message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, a1, b1);
            var checksum = checksum(message, group.q());

            var challenge1 = checksum.subtract(challenge0).mod(group.q());
            var response1 = w.subtract(ctSigma.r().multiply(challenge1)).mod(group.q());
            var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
            var proof1 = Proof.builder().challenge(challenge1).response(response1).build();
            return List.of(proof0, proof1);

        } else {
            var challenge1 = GenRandomInteger.run(group.q());
            var response1 = GenRandomInteger.run(group.q());

            var a1 = group.g().modPow(response1, group.p())
                .multiply(ctSigma.alpha().modPow(challenge1, group.p())).mod(group.p());
            var b1 = publicKey.y().modPow(response1, group.p())
                .multiply(ctSigma.beta().multiply(group.g().modInverse(group.p()))
                    .modPow(challenge1, group.p()))
                .mod(group.p());
            var w = GenRandomInteger.run(group.q());
            var a0 = group.g().modPow(w, group.p());
            var b0 = publicKey.y().modPow(w, group.p());

            String message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, a1, b1);
            var checksum = checksum(message, group.q());

            var challenge0 = checksum.subtract(challenge1).mod(group.q());
            var response0 = w.subtract(ct0.r().multiply(challenge0)).mod(group.q());
            var proof0 = Proof.builder().challenge(challenge0).response(response0).build();
            var proof1 = Proof.builder().challenge(challenge1).response(response1).build();
            return List.of(proof0, proof1);
        }
    }

    public static String createElectionHash(Election election) {
        try {
            var json = JsonMapper.INSTANCE.writeValueAsString(election);
            var digest = MessageDigest.getInstance("SHA-256");
            var encodedhash = digest.digest(json.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().withoutPadding().encodeToString(encodedhash);

        } catch (IOException exc) {
            throw new IllegalStateException("cannot serialize election", exc);
        } catch (NoSuchAlgorithmException exc) {
            throw new IllegalStateException("cannot compute digest", exc);
        }
    }

    public static Signature createSignature(List<Answer> answers, Credentials credentials,
        Election election) {

        Group group = election.publicKey().group();
        BigInteger secretKey = GenCredentials.toSecretKey(credentials.privateCred(), election.uuid(), group);

        var w = GenRandomInteger.run(group.q());
        var a = group.g().modPow(w, group.p());

        String text = answers.stream().flatMap(answer -> answer.choices().stream())
            .map(c -> c.alpha() + "," + c.beta())
            .collect(Collectors.joining(","));

        String message = String.format("sig|%s|%s|%s", credentials.publicCred(), a, text);
        var challenge = checksum(message, group.q());
        var response = w.subtract(secretKey.multiply(challenge)).mod(group.q());

        return Signature.builder()
            .publicKey(credentials.publicCred())
            .challenge(challenge)
            .response(response)
            .build();
    }
}
