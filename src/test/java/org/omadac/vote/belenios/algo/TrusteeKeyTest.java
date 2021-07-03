package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.Proof;
import org.omadac.vote.belenios.model.TrusteeKeyPair;
import org.omadac.vote.belenios.model.TrusteePublicKey;

public class TrusteeKeyTest {

    private static final String DIR = "src/test/resources/4BmyrdywTpwJry";
    private Group group = Groups.HOMOMORPHIC;

    @Test
    public void foo() throws NoSuchAlgorithmException {
        String privateKey = "47663895767201702907625612414185978205585858428381657990435036965748868986818";
        String publicKey = "4645211384453782098238007232316938511061664286399777814058366628874075967069109426419345272160883516167640884377593363578041294488014270349084510837865348249893197690309538977798622888655867630785457488002991096351714579681197035560440983036372033655183731858322145655422761716553866940782174156664303282593046023593065723722077032187903897485541705726414481776616977768866170288762218082372205089577325931066439766446769004089899559646194897941627494911916693726790147249756459537587258610320224737803048972569536084317993129706000409063633402975094345480561884467760793269752280030985050289727335209169625583549556";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(publicKey.getBytes(StandardCharsets.UTF_8));

        String keyId = Hex.bytesToHex(encodedhash).substring(0, 8);
        assertThat(keyId).isEqualTo("19B46B98");

        BigInteger privKey = new BigInteger(privateKey);
        BigInteger pubKey = group.g().modPow(privKey, group.p());
        assertThat(pubKey).isEqualTo(publicKey);

        var challenge = new BigInteger("63927280939860978903064758552838380017425397976503877948445018169990377905147");
        var response = new BigInteger("61899678553699875386298524482495635368456257494822752952788876892322896717017");

        var proof = Proof.builder().challenge(challenge).response(response).build();
        var trusteePublicKey = TrusteePublicKey.builder().publicKey(pubKey).pok(proof).build();
        assertThat(GenTrusteeKey.isValid(group, trusteePublicKey)).isTrue();
    }

    @Test
    public void roundTrip() {
        TrusteeKeyPair keyPair = GenTrusteeKey.genKeyPair(group);
        assertThat(keyPair.id()).hasSize(8);
        assertThat(GenTrusteeKey.isValid(group, keyPair.trusteePublicKey())).isTrue();
    }

    @Test
    public void readJsonString() throws IOException {
        var key = JsonMapper.INSTANCE.readValue(new File(DIR, "8A687CA2.privkey"), String.class);
        assertThat(key).isEqualTo("45808391183982415395165525244185134133799101543379447681158860342942626483434");
    }
}
