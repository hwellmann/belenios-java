package org.omadac.vote.belenios.cli;

import java.io.File;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.TrusteePublicKey;
import org.omadac.vote.belenios.model.WrappedPublicKey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "mkelection", mixinStandardHelpOptions = true, description = "This command reads and checks public_keys.jsons (or threshold.json if\n"
    + "it exists). It then computes the global election public key and\n"
    + "generates an election.json file.\n\n")
public class Mkelection implements Callable<Integer> {

    @Option(names = {"--group"}, description = "Take group parameters from file GROUP", required = true)
    private File group;

    @Option(names = {"--uuid"}, description = "UUID of the election", required = true)
    private String uuid;

    @Option(names = {
        "--template"}, description = "Read identities from FILE. One credential will be generated for each line of FILE", required = true)
    private File template;

    private TrusteePublicKey toPublicKeys(List<Object> trustee) {
        if ("Single".equals(trustee.get(0))) {
            try {
                String json = JsonMapper.INSTANCE.writeValueAsString(trustee.get(1));
                return JsonMapper.INSTANCE.readValue(json, TrusteePublicKey.class);
            } catch (JsonProcessingException exc) {
                throw new IllegalArgumentException(exc);
            }
        }
        return null;
    }

    @Override
    public Integer call() throws Exception {
        Group g = JsonMapper.INSTANCE.readValue(group, Group.class);
        Election election = JsonMapper.INSTANCE.readValue(template, Election.class);
        List<List<Object>> trustees = JsonMapper.INSTANCE.readValue(new File("trustees.json"),
            new TypeReference<>() {});
        BigInteger y = trustees.stream()
            .map(this::toPublicKeys)
            .map(pk -> pk.publicKey())
            .reduce(BigInteger.ONE, BigInteger::multiply)
            .mod(g.p());
        WrappedPublicKey publicKey = WrappedPublicKey.builder().y(y).group(g).build();
        election = election.withPublicKey(publicKey).withUuid(uuid);
        JsonMapper.INSTANCE.writeValue(new File("election.json"), election);
        return 0;
    }
}