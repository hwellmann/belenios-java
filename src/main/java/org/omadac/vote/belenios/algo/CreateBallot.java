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

import org.graalvm.collections.Pair;
import org.omadac.vote.belenios.model.Answer;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.CiphertextAndSecret;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.Question;
import org.omadac.vote.belenios.model.Signature;
import org.omadac.vote.belenios.model.WrappedPublicKey;

public class CreateBallot {

    public static Ballot createBallot(Election election, Credentials credentials,
        List<List<Integer>> rawVotes) {
        if (election.questions().size() != rawVotes.size()) {
            throw new IllegalArgumentException("Incorrect number of answers");
        }
        List<Answer> answers = new ArrayList<>();
        for (int i = 0; i < rawVotes.size(); i++) {
            var question = election.questions().get(i);
            var rawVote = rawVotes.get(i);
            var answer = createAnswer(election.publicKey(), credentials.publicCred(), question, rawVote);
            answers.add(answer);
        }
        Signature signature = createSignature(answers, credentials, election);

        return Ballot.builder()
            .answers(answers)
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
        var choicesAndSecrets = choicesAndProofs.stream().map(Pair::getLeft).collect(toList());
        var choices = choicesAndProofs.stream().map(Pair::getLeft).map(CiphertextAndSecret::ciphertext)
            .collect(toList());
        var proofs = choicesAndProofs.stream().map(Pair::getRight).collect(toList());

        var ct0 = choicesAndSecrets.get(0);
        var ctSigma = choicesAndSecrets.stream().skip(1)
            .reduce((left, right) -> left.combine(right, publicKey.group().p())).get();

        var prefix = Stream
            .of(publicKey.group().g(), publicKey.y(), ct0.alpha(), ct0.beta(), ctSigma.alpha(), ctSigma.beta())
            .map(BigInteger::toString)
            .collect(Collectors.joining(","));

        var builder = Answer.builder()
            .choices(choices)
            .individualProofs(proofs)
            .overallProof(createOverallProof(publicKey, publicCred, ct0, ctSigma, rawVote.get(0), prefix));

        if (question.blankAnswerAllowed()) {
            builder.blankProof(createBlankProof(publicKey, publicCred, ct0, ctSigma, rawVote.get(0), prefix))
                .overallProof(createOverallProof(publicKey, publicCred, ct0, ctSigma, rawVote.get(0), prefix));
        } else {
            Integer choice = rawVote.stream().reduce(0, Integer::sum);
            builder.overallProof(createIntervalProof(publicKey, publicCred, ctSigma, choice, question.min(), question.max()));
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
        List<Proof> proofs = createIntervalProof(publicKey, publicCred, ct, rawVote, 0, 1);
        return Pair.create(ct, proofs);
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

    private static List<Proof> createIntervalProof(WrappedPublicKey publicKey, BigInteger publicCred,
        CiphertextAndSecret ct, int choice, int min, int max) {
        List<Proof> proofs = new ArrayList<>();
        List<Ciphertext> abs = new ArrayList<>();
        var group = publicKey.group();
        for (int j = min; j <= max; j++) {
            if (j == choice) {
                var proof = Proof.builder().challenge(BigInteger.ZERO).response(BigInteger.ZERO).build();
                proofs.add(proof);

                var ab = Ciphertext.builder().alpha(BigInteger.ZERO).beta(BigInteger.ZERO).build();
                abs.add(ab);
            } else {
                var challenge = GenRandomInteger.run(group.q());
                var response = GenRandomInteger.run(group.q());
                var proof = Proof.builder().challenge(challenge).response(response).build();
                proofs.add(proof);

                var a1Num = group.g().modPow(response, group.p());
                var aDenom = ct.alpha().modPow(challenge, group.p());
                var a = a1Num.multiply(aDenom.modInverse(group.p())).mod(group.p());

                var bNum = publicKey.y().modPow(response, group.p());
                var bDenom = ct.beta().multiply(group.g().modInverse(group.p()).modPow(BigInteger.valueOf(j), group.p()))
                    .modPow(challenge, group.p());
                var b = bNum.multiply(bDenom.modInverse(group.p())).mod(group.p());
                
                var ab = Ciphertext.builder().alpha(a).beta(b).build();
                abs.add(ab);            
            }
        }
        int i = choice - min;
        var w = GenRandomInteger.run(group.q());
        var ai = group.g().modPow(w, group.p());
        var bi = publicKey.y().modPow(w, group.p());
        var abi = Ciphertext.builder().alpha(ai).beta(bi).build();
        abs.set(i, abi);

        var message = String.format("prove|%s|%s,%s|", publicCred.toString(),
        ct.alpha().toString(), ct.beta().toString());
        for (Ciphertext ab : abs) {
            message += (ab.alpha() + "," + ab.beta() + ",");
        }
        message = message.substring(0, message.length() - 1);
        var checksum = checksum(message, group.q());

        var challengeSum = proofs.stream().map(Proof::challenge).reduce(BigInteger.ZERO, BigInteger::add);
        var challengei = checksum.subtract(challengeSum).mod(group.q());
        var responsei = challengei.multiply(ct.r()).add(w).mod(group.q());
        var proofi = Proof.builder().challenge(challengei).response(responsei).build();
        proofs.set(i, proofi);
            
        return proofs;    
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

            var message = String.format("bproof0|%s|%s|%s,%s,%s,%s", publicCred, P, a0, b0, aSigma, bSigma);
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

            var message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, a1, b1);
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

            var message = String.format("bproof1|%s|%s|%s,%s,%s,%s", publicCred, prefix, a0, b0, a1, b1);
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

        var group = election.publicKey().group();
        var secretKey = GenCredentials.toSecretKey(credentials.privateCred(), election.uuid(), group);

        var w = GenRandomInteger.run(group.q());
        var a = group.g().modPow(w, group.p());

        var text = answers.stream().flatMap(answer -> answer.choices().stream())
            .map(c -> c.alpha() + "," + c.beta())
            .collect(Collectors.joining(","));

        var message = String.format("sig|%s|%s|%s", credentials.publicCred(), a, text);
        var challenge = checksum(message, group.q());
        var response = w.subtract(secretKey.multiply(challenge)).mod(group.q());

        return Signature.builder()
            .publicKey(credentials.publicCred())
            .challenge(challenge)
            .response(response)
            .build();
    }
}
