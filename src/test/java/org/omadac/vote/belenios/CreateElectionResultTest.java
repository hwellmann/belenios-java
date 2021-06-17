package org.omadac.vote.belenios;

import static org.assertj.core.api.Assertions.assertThat;
import static org.omadac.vote.belenios.CreateBallot.createBallot;
import static org.omadac.vote.belenios.CreateElectionResult.createResult;
import static org.omadac.vote.belenios.CreateEncryptedTally.tally;
import static org.omadac.vote.belenios.CreatePartialDecryption.decrypt;
import static org.omadac.vote.belenios.GenCredentials.generateToken;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.PartialDecryption;
import org.omadac.vote.belenios.model.Question;
import org.omadac.vote.belenios.model.Result;
import org.omadac.vote.belenios.model.TrusteeKeyPair;
import org.omadac.vote.belenios.model.WrappedPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CreateElectionResultTest {

    private static Logger log = LoggerFactory.getLogger(CreateElectionResultTest.class);
    private Group group = Groups.HOMOMORPHIC;

    @Test
    public void shouldCreateResult() {
        log.info("Starting");

        log.info("Generating trustee keys");
        TrusteeKeyPair keyPair = GenTrusteeKey.genKeyPair(group);
        WrappedPublicKey publicKey = WrappedPublicKey.builder()
            .y(keyPair.trusteePublicKey().publicKey())
            .group(group)
            .build();

        log.info("Generating election");
        Question question = Question.builder()
            .question("Question 1")
            .addAnswers("Answer 1", "Answer 2")
            .max(1)
            .min(1)
            .blank(true)
            .build();

        Election election = Election.builder()
            .publicKey(publicKey)
            .uuid(generateToken())
            .addQuestion(question)
            .administrator("admin")
            .credentialAuthority("server")
            .description("test")
            .name("test")
            .build();

        List<Credentials> credentials = new ArrayList<>();
        List<Ballot> ballots = new ArrayList<>();

        int numVoters = 1000;
        log.info("Generating {} credentials", numVoters);
        for (int i = 0; i < numVoters; i++) {
            Credentials cred = GenCredentials.generate(election.uuid(), group);
            credentials.add(cred);
        }

        log.info("Generating {} ballots", numVoters);
        for (int i = 0; i < numVoters; i++) {
            Ballot ballot = createBallot(election, credentials.get(i), List.of(List.of(0, 0, 1)));
            ballots.add(ballot);
        }

        log.info("Verifying {} ballots", numVoters);
        for (Ballot ballot: ballots) {
            VerifyBallot.verifyBallot(ballot, election);
        }

        log.info("Creating encrypted tally");
        List<List<Ciphertext>> tally = tally(election, ballots.stream());

        log.info("Creating decryptions");
        PartialDecryption decryption = decrypt(election, keyPair, tally);

        log.info("Verifying decryptions");
        assertThat(CreatePartialDecryption.verify(election, keyPair, tally, decryption)).isTrue();

        log.info("Creating result");
        Result result = createResult(election, numVoters, tally, List.of(decryption));
        log.info("Done");

        assertThat(result.numTallied()).isEqualTo(numVoters);
        assertThat(result.result()).isEqualTo(List.of(List.of(0, 0, numVoters)));
    }

    @Test
    public void shouldCreateResultWithTwoTrustees() {
        log.info("Starting");

        log.info("Generating trustee keys");
        TrusteeKeyPair keyPair1 = GenTrusteeKey.genKeyPair(group);
        WrappedPublicKey publicKey1 = WrappedPublicKey.builder()
            .y(keyPair1.trusteePublicKey().publicKey())
            .group(group)
            .build();

        TrusteeKeyPair keyPair2 = GenTrusteeKey.genKeyPair(group);
        WrappedPublicKey publicKey2 = WrappedPublicKey.builder()
            .y(keyPair2.trusteePublicKey().publicKey())
            .group(group)
            .build();

        log.info("Generating election");
        Question question = Question.builder()
            .question("Question 1")
            .addAnswers("Answer 1", "Answer 2")
            .max(1)
            .min(1)
            .blank(true)
            .build();

        var y = publicKey1.y().multiply(publicKey2.y()).mod(group.p());
        var publicKey = publicKey1.withY(y);

        Election election = Election.builder()
            .publicKey(publicKey)
            .uuid(generateToken())
            .addQuestion(question)
            .administrator("admin")
            .credentialAuthority("server")
            .description("test")
            .name("test")
            .build();

        List<Credentials> credentials = new ArrayList<>();
        List<Ballot> ballots = new ArrayList<>();

        int numVoters = 3;
        log.info("Generating {} credentials", numVoters);
        for (int i = 0; i < numVoters; i++) {
            Credentials cred = GenCredentials.generate(election.uuid(), group);
            credentials.add(cred);
        }

        log.info("Generating {} ballots", numVoters);
        for (int i = 0; i < numVoters; i++) {
            Ballot ballot = createBallot(election, credentials.get(i), List.of(List.of(0, 0, 1)));
            ballots.add(ballot);
        }

        log.info("Verifying {} ballots", numVoters);
        for (Ballot ballot: ballots) {
            VerifyBallot.verifyBallot(ballot, election);
        }

        log.info("Creating encrypted tally");
        List<List<Ciphertext>> tally = tally(election, ballots.stream());

        log.info("Creating decryptions");
        PartialDecryption decryption1 = decrypt(election, keyPair1, tally);
        PartialDecryption decryption2 = decrypt(election, keyPair2, tally);

        log.info("Verifying decryptions");
        assertThat(CreatePartialDecryption.verify(election, keyPair1, tally, decryption1)).isTrue();
        assertThat(CreatePartialDecryption.verify(election, keyPair2, tally, decryption2)).isTrue();

        log.info("Creating result");
        Result result = createResult(election, numVoters, tally, List.of(decryption1, decryption2));
        log.info("Done");

        assertThat(result.numTallied()).isEqualTo(numVoters);
        assertThat(result.result()).isEqualTo(List.of(List.of(0, 0, numVoters)));
    }

}
