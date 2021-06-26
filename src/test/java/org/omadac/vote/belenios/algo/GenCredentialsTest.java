package org.omadac.vote.belenios.algo;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Group;

public class GenCredentialsTest {

    Group group = Groups.HOMOMORPHIC;

    @Test
    public void isValid() {
        assertThat(GenCredentials.isValid("NYC-SgM-axC-fCu-pvP")).isTrue();
        assertThat(GenCredentials.isValid("egc-hNc-GvW-E33-KCp")).isTrue();
    }

    @Test
    public void shouldDerive() throws Exception {
        BigInteger publicKey = GenCredentials.derive("NYC-SgM-axC-fCu-pvP", "deT9e32LvYeDzg", group);

        assertThat(publicKey).isEqualTo(
            "18667433505891368444045681325118240780405413018316493595944581691395145795469910988018109282526836201431377145866938727438337586676882723360013990050927636596691479841881190944139233579365430124720754185764408528755973078066310572602927484461363076614780455134342898235367140064537201194778176569237605603479012862200552645175160468150869968164502986855792639330286141968255374480179981074520018482845319714457416318209431743934366799385354652712072062212321719192256473038054222098698853696430702846645496164890685457434787351103800389525349979380810417855564866389400639709847784591992025398763557606403431736347696");

    }

    @Test
    public void shouldGenerate() {
        String uuid = UUID.randomUUID().toString();
        Credentials credentials = GenCredentials.generate(uuid, group);
        assertThat(GenCredentials.isValid(credentials.privateCred())).isTrue();
        assertThat(GenCredentials.derive(credentials.privateCred(), uuid, group)).isEqualTo(credentials.publicCred());
        BigInteger secretKey = GenCredentials.toSecretKey(credentials.privateCred(), uuid, group);
        assertThat(group.g().modPow(secretKey, group.p())).isEqualTo(credentials.publicCred());
    }
}
